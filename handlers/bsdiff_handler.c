/*
 * (C) Copyright 2020
 * Robert Swain <robert.swain@gmail.com>
 * Jimmy Wahlberg <jimmy.wahlberg@gmail.com>
 *
 * SPDX-License-Identifier:     MIT
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <zstd.h>

#include "bsdiff/bspatch.h"
#include "handler.h"
#include "swupdate.h"
#include "util.h"

typedef struct patch_data_t {
	uint8_t *patch_buf;
	size_t patch_len;
	size_t patch_offset;
	ZSTD_DStream *zds;
	size_t z_read_len;
	uint8_t *raw_buf;
	size_t raw_len;
	size_t raw_offset;
} patch_data_t;

int patch_data_read_cb(void *out, const void *buf, unsigned int len)
{
	patch_data_t *pd = (patch_data_t *)out;

	if (len > pd->patch_len - pd->patch_offset) {
		ERROR("copyfile tried to read more data than expected");
		return -1;
	}

	memcpy(pd->patch_buf + pd->patch_offset, buf, len);
	pd->patch_offset += len;

	// FIXME - do we have to free buf?
	return 0;
}

int bspatch_read_cb(const struct bspatch_stream *stream,
					void *buffer, int length)
{
	patch_data_t *pd = (patch_data_t *)stream->opaque;
	size_t bytes_requested = length;
	size_t raw_avail = 0;
	size_t bytes_to_read = 0;
	size_t ret = 0;
	ZSTD_inBuffer input = {};
	ZSTD_outBuffer output = {};

	while (bytes_requested > 0) {
		if (pd->raw_len - pd->raw_offset < 1) {
			// decompress input block from patch buf at patch offset into raw buf at raw offset
			if (pd->z_read_len > pd->patch_len - pd->patch_offset) {
				ERROR("Tried to decompress more data than was available: %u > %u - %u = %u",
					pd->z_read_len,
					pd->patch_len,
					pd->patch_offset,
					pd->patch_len - pd->patch_offset);
				return -1;
			}
			pd->raw_offset = 0;

			input.src = pd->patch_buf + pd->patch_offset;
			input.size = pd->z_read_len; // FIXME - should be patch_len - patch_offset?
			input.pos = 0;
			output.dst = pd->raw_buf;
			output.size = pd->raw_len;
			output.pos = 0;

			ret = ZSTD_decompressStream(pd->zds, &output, &input);
			if (ret < 0) {
				ERROR("Failed to decompress patch data: %u", ret);
				return -1;
			} else if (ret > 0) {
				// NOTE: This should never happen due to raw_buf being ZSTD_DStreamOutSize() large!
				ERROR("Failed to decompress a complete block: %u", ret);
				return -1;
			}

			pd->patch_offset += input.pos;
			if (output.pos == output.size) {
				// Data left in internal buffers, calling again to flush
				ret = ZSTD_decompressStream(pd->zds, &output, &input);
				if (ret < 0) {
					ERROR("Failed to decompress patch data: %u", ret);
					return -1;
				} else if (ret > 0) {
					// NOTE: This shoulu never happen due to raw_buf being ZSTD_DStreamOutSize() large!
					ERROR("Failed to decompress a complete block: %u", ret);
					return -1;
				}
			}
		}
		// if length data is available in the uncompressed buffer, read it into buffer
		raw_avail = pd->raw_len - pd->raw_offset;
		bytes_to_read = bytes_requested < raw_avail ? bytes_requested : raw_avail;
		memcpy(buffer, pd->raw_buf + pd->raw_offset, bytes_to_read);
		pd->raw_offset += bytes_to_read;
		bytes_requested -= bytes_to_read;
		// if partial, read that then read another compressed block, decompress
	}

	return 0;
}

int bsdiff_handler(struct img_type *img,
		void __attribute__ ((__unused__)) *data)
{
	int ret = 0;
	char *src_filename = NULL;
	char *chunk_size_str = NULL;
	size_t chunk_size = 0;
	FILE *src_file = NULL;
	FILE *dst_file = NULL;
	uint8_t *src_data = NULL;
	uint8_t *dst_data = NULL;
	patch_data_t pd = { NULL, 0, 0, NULL, 0, NULL, 0, 0 };
	size_t patch_size = 0;
	struct bspatch_stream bspatch_data = {};
	size_t bytes_read = 0;
	size_t bytes_written = 0;

	// Parse the sw-description fields

	if (img->seek) {
		ERROR("Option 'seek' is not supported for bsdiff.");
		return -1;
	}

	src_filename = dict_get_value(&img->properties, "bsdiffsrc");
	if (src_filename == NULL) {
		ERROR("Property 'bsdiffsrc' is missing in sw-description.");
		return -1;
	}

	chunk_size_str = dict_get_value(&img->properties, "chunk_size");
	if (chunk_size_str == NULL) {
		//
	}
	chunk_size = strtoul(chunk_size_str, NULL, 10);

	// Open files

	dst_file = NULL;
	if ((dst_file = fopen(img->device, "wb+")) == NULL) {
		ERROR("%s cannot be opened for writing: %s", img->device, strerror(errno));
		return -1;
	}

	src_file = NULL;
	if ((src_file = fopen(src_filename, "rb+")) == NULL) {
		ERROR("%s cannot be opened for reading: %s", src_filename, strerror(errno));
		ret = -1;
		goto cleanup;
	}

	// Load the patch data from the package

	pd.patch_len = img->size;
	pd.patch_buf = (uint8_t *)malloc(pd.patch_len);
	if (!pd.patch_buf) {
		ERROR("Failed to allocate patch buffer");
		goto cleanup;
	}
	pd.patch_offset = 0;

	ret = copyfile(img->fdin,
				   &pd,
				   img->size,
				   (unsigned long *)&img->offset,
				   img->seek,
				   0, /* no skip */
				   img->compressed,
				   &img->checksum,
				   img->sha256,
				   img->is_encrypted,
				   patch_data_read_cb);
	if (ret) {
		ERROR("Error %d reading bsdiff patch, aborting.", ret);
		goto cleanup;
	}

	// Prepare for patch application

	// Check bsdiff magic
	if (pd.patch_len < 24) {
		ERROR("Corrupt patch: patch is too small: %u", pd.patch_len);
		goto cleanup;
	}
	if (memcmp(pd.patch_buf, "ENDSLEY/BSDIFF43", 16) != 0) {
		ERROR("Corrupt patch: patch magic does not match");
		goto cleanup;
	}
	patch_size = offtin(pd.patch_buf + 16);
	if (patch_size < 0) {
		ERROR("Corrupt patch: patch size invalid: %d", patch_size);
		goto cleanup;
	}
	pd.patch_offset = 24;

	// Initialize ZSTD
	pd.zds = ZSTD_createDStream();
	pd.z_read_len = ZSTD_initDStream(pd.zds);
	pd.raw_len = ZSTD_DStreamOutSize();
	pd.raw_buf = (uint8_t *)malloc(pd.raw_len);
	if (!pd.raw_buf) {
		ERROR("Failed to allocate decompression buffer.");
		goto cleanup;
	}
	pd.raw_offset = 0;

	bspatch_data.opaque = &pd;
	bspatch_data.read = bspatch_read_cb;

	// Read source and destination data
	src_data = (uint8_t *)malloc(chunk_size * sizeof(uint8_t));
	// FIXME - seek to offset point in input
	bytes_read = fread(src_data, 1, chunk_size, src_file);

	if (bytes_read != chunk_size) {
		ERROR("Read fewer bytes %u than chunk_size %u", bytes_read, chunk_size);
		// FIXME - how to handle this
		goto cleanup;
	}
	dst_data = (uint8_t *)malloc(chunk_size * sizeof(uint8_t));

	// Apply the patch

	ret = bspatch(src_data, chunk_size, dst_data, patch_size, &bspatch_data);
	if (ret) {
		ERROR("Error %d applying bsdiff patch, aborting.", ret);
		goto cleanup;
	}

	// seek to seek point in output
	bytes_written = fwrite(dst_data, 1, chunk_size, dst_file);

	if (bytes_written != chunk_size) {
		ERROR("Wrote fewer bytes %u than chunk_size %u", bytes_written, chunk_size);
		// FIXME - how to handle this
		goto cleanup;
	}

cleanup:
	if (src_file) {
		if (fclose(src_file) == EOF) {
			ERROR("Error while closing bsdiffsrc: %s", strerror(errno));
		}
	}
	if (dst_file) {
		if (fclose(dst_file) == EOF) {
			ERROR("Error while closing device: %s", strerror(errno));
		}
	}
	if (src_data) {
		free(src_data);
		src_data = NULL;
	}
	if (dst_data) {
		free(dst_data);
		dst_data = NULL;
	}
	if (pd.patch_buf) {
		free(pd.patch_buf);
	}
	if (pd.zds) {
		ZSTD_freeDStream(pd.zds);
	}
	if (pd.raw_buf) {
		free(pd.raw_buf);
	}
	return ret;
}

// int copyfile(int fdin, int fdout, int nbytes, unsigned long *offs,
//		 int skip_file, int compressed, uint32_t *checksum, unsigned char *hash);

__attribute__((constructor))
void bsdiff_handler_init(void)
{
		register_handler("bsdiff_image", bsdiff_handler, IMAGE_HANDLER, NULL);
}
