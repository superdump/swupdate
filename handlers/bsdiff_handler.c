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

#include <archive.h>
#include <archive_entry.h>

#include "bsdiff/bspatch.h"
#include "handler.h"
#include "swupdate.h"
#include "util.h"

typedef struct patch_data_t {
	uint8_t *patch_buf;
	size_t patch_len;
	size_t patch_offset;
	struct archive *compressed;
	uint8_t *raw_buf;
	size_t raw_len;
	size_t raw_offset;
} patch_data_t;

int patch_data_read_cb(void *out, const void *buf, unsigned int len);
int bspatch_read_cb(const struct bspatch_stream *stream,
					void *buffer, int length);
int bsdiff_handler(struct img_type *img,
		void __attribute__ ((__unused__)) *data);
void bsdiff_handler_init(void);

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
	ssize_t bytes_read = 0;

	while (bytes_requested > 0) {
		if (pd->raw_offset >= pd->raw_len) {
			// decompress input block from patch buf at patch offset into raw buf at raw offset
			pd->raw_offset = 0;

			bytes_read = archive_read_data(pd->compressed, pd->raw_buf, pd->raw_len);
			if (bytes_read < 0) {
				ERROR("archive_read_data(): %s %d", archive_error_string(pd->compressed), bytes_read);
				return -1;
			} else if (bytes_read == 0) {
				// NOTE: This should never happen
				ERROR("Patch is corrupt - tried to read more data than available");
				return -1;
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
	patch_data_t pd = { NULL, 0, 0, NULL, NULL, 0, 0 };
	size_t patched_size = 0;
	struct bspatch_stream bspatch_data = {};
	size_t bytes_read = 0;
	size_t bytes_written = 0;
	struct archive_entry *entry;

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
		ret = -1;
		goto cleanup;
	}
	if (memcmp(pd.patch_buf, "ENDSLEY/BSDIFF43", 16) != 0) {
		ERROR("Corrupt patch: patch magic does not match");
		ret = -1;
		goto cleanup;
	}
	patched_size = offtin(pd.patch_buf + 16);
	if (patched_size < 0) {
		ERROR("Corrupt patch: patch size invalid: %d", patched_size);
		ret = -1;
		goto cleanup;
	}
	pd.patch_offset = 24;

	// Initialize libarchive
	pd.compressed = archive_read_new();
	archive_read_support_filter_all(pd.compressed);
	archive_read_support_format_raw(pd.compressed);
	ret = archive_read_open_memory(pd.compressed, pd.patch_buf + pd.patch_offset, pd.patch_len - pd.patch_offset);
	if (ret) {
		ERROR("archive_read_open_memory(): %s %d", archive_error_string(pd.compressed), ret);
		goto cleanup;
	}

	// NOTE: Here we make an assumption that the patch only contains one entry!
	ret = archive_read_next_header(pd.compressed, &entry);
	if (ret == ARCHIVE_EOF) {
		ERROR("Compressed part of patch was unable to decompress");
		goto cleanup;
	} else if (ret != ARCHIVE_OK) {
		ERROR("archive_read_next_header(): %s %d", archive_error_string(pd.compressed), ret);
		goto cleanup;
	}

	// Allocate 1MB buffer to decompress into
	pd.raw_len = 1 << 20;
	pd.raw_buf = (uint8_t *)malloc(pd.raw_len);
	// Initialize raw_offset to raw_len to trigger decompression
	pd.raw_offset = pd.raw_len;

	bspatch_data.opaque = &pd;
	bspatch_data.read = bspatch_read_cb;

	// Read source and destination data
	src_data = (uint8_t *)malloc(chunk_size * sizeof(uint8_t));
	// FIXME - seek to offset point in input
	bytes_read = fread(src_data, 1, chunk_size, src_file);
	if (bytes_read != chunk_size) {
		ERROR("Read fewer bytes %u than chunk_size %u", bytes_read, chunk_size);
		ret = -1;
		goto cleanup;
	}

	dst_data = (uint8_t *)malloc(patched_size * sizeof(uint8_t));

	// Apply the patch

	ret = bspatch(src_data, chunk_size, dst_data, patched_size, &bspatch_data);
	if (ret) {
		ERROR("Error %d applying bsdiff patch, aborting.", ret);
		goto cleanup;
	}

	// FIXME - seek to seek point in output
	bytes_written = fwrite(dst_data, 1, patched_size, dst_file);

	if (bytes_written != patched_size) {
		ERROR("Wrote fewer bytes %u than patched_size %u", bytes_written, patched_size);
		ret = -1;
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
	if (pd.compressed) {
		archive_read_close(pd.compressed);
		archive_read_free(pd.compressed);
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
