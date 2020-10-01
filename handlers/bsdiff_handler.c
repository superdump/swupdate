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

#include "bsdiff/bspatch.h"
#include "handler.h"
#include "swupdate.h"
#include "util.h"

typedef struct patch_data_t {
	uint8_t *buf;
	size_t len;
	size_t write_offset;
	size_t read_offset;
} patch_data_t;

int patch_data_read_cb(void *out, const void *buf, unsigned int len)
{
	patch_data_t *pd = (patch_data_t *)out;

	if (len > pd->len - pd->write_offset) {
		ERROR("copyfile tried to read more data than expected");
		return -1;
	}

	memcpy(pd->buf + pd->write_offset, buf, len);
	pd->write_offset += len;

	// FIXME - do we have to free buf?
	return 0;
}

int bspatch_read_cb(const struct bspatch_stream *stream,
					void *buffer, int length)
{
	patch_data_t *pd = (patch_data_t *)stream->opaque;

	if (length > pd->len - pd->read_offset) {
		// FIXME - print values
		ERROR("bspatch tried to read more data than expected");
		return -1;
	}

	memcpy(buffer, pd->buf + pd->read_offset, length);
	pd->read_offset += length;

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
	patch_data_t pd = {};
	struct bspatch_stream bspatch_data = {};

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

	dst_file = NULL;
	if ((dst_file = fopen(img->device, "wb+")) == NULL) {
		ERROR("%s cannot be opened for writing: %s", img->device, strerror(errno));
		return -1;
	}

	src_file = NULL;
	if ((src_file = fopen(src_filename, "rb+")) == NULL) {
		ERROR("%s cannot be opened for reading: %s", src_file, strerror(errno));
		ret = -1;
		goto cleanup;
	}

	pd.buf = (uint8_t *)malloc(img->size * sizeof(uint8_t));
	pd.len = img->size;
	pd.write_offset = 0;
	pd.read_offset = 24;

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

	bspatch_data.opaque = &pd;
	bspatch_data.read = bspatch_read_cb;

	src_data = (uint8_t *)malloc(chunk_size * sizeof(uint8_t));
	// FIXME - seek to offset point in input
	size_t bytes_read = fread(src_data, 1, chunk_size, src_file);

	if (bytes_read != chunk_size) {
		ERROR("Read fewer bytes %ld than chunk_size %ld", bytes_read, chunk_size);
		// FIXME - how to handle this
	}
	dst_data = (uint8_t *)malloc(chunk_size * sizeof(uint8_t));
       // FIXME - Read the newsize from the patchemything
	ret = bspatch(src_data, chunk_size, dst_data, chunk_size, &bspatch_data);
	if (ret) {
		ERROR("Error %d applying bsdiff patch, aborting.", ret);
		goto cleanup;
	}

	// seek to seek point in output
	size_t bytes_written = fwrite(dst_data, 1, chunk_size, dst_file);

	if (bytes_written != chunk_size) {
		ERROR("Wrote fewer bytes %ld than chunk_size %ld", bytes_written, chunk_size);
		// FIXME - how to handle this
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
	return ret;
}

// int copyfile(int fdin, int fdout, int nbytes, unsigned long *offs,
//		 int skip_file, int compressed, uint32_t *checksum, unsigned char *hash);

__attribute__((constructor))
void bsdiff_handler_init(void)
{
		register_handler("bsdiff_image", bsdiff_handler, IMAGE_HANDLER, NULL);
}
