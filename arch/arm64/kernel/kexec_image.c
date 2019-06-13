// SPDX-License-Identifier: GPL-2.0
/*
 * Kexec image loader

 * Copyright (C) 2018 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 */

#define pr_fmt(fmt)	"kexec_file(Image): " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/pe.h>
#include <linux/string.h>
#include <linux/verification.h>
#include <asm/byteorder.h>
#include <asm/cpufeature.h>
#include <asm/image.h>
#include <asm/memory.h>

static int image_probe(const char *kernel_buf, unsigned long kernel_len)
{
	const struct arm64_image_header *h =
		(const struct arm64_image_header *)(kernel_buf);

	pr_info("BHUPESH, 0, Inside %s\n", __func__);
	if (!h || (kernel_len < sizeof(*h))) {
		pr_info("BHUPESH, 0a, Inside %s, ret=-EINVAL\n", __func__);
		return -EINVAL;
	}
	pr_info("BHUPESH, 0b, Inside %s, &h->magic=0x%x\n", __func__, *(&h->magic));

	if (memcmp(&h->magic, ARM64_IMAGE_MAGIC, sizeof(h->magic))) {
		pr_info("BHUPESH, 0c, Inside %s, ret=-EINVAL, &h->magic=0x%x\n", __func__, *(&h->magic));
		return -EINVAL;
	}

	return 0;
}

static void *image_load(struct kimage *image,
				char *kernel, unsigned long kernel_len,
				char *initrd, unsigned long initrd_len,
				char *cmdline, unsigned long cmdline_len)
{
	struct arm64_image_header *h;
	u64 flags, value;
	bool be_image, be_kernel;
	struct kexec_buf kbuf;
	unsigned long text_offset;
	struct kexec_segment *kernel_segment;
	int ret;

	pr_info("BHUPESH, 1, Inside %s\n", __func__);

	/* We don't support crash kernels yet. */
	if (image->type == KEXEC_TYPE_CRASH) {
		pr_info("BHUPESH, 1a, Inside %s\n", __func__);
		return ERR_PTR(-EOPNOTSUPP);
	}

	/*
	 * We require a kernel with an unambiguous Image header. Per
	 * Documentation/booting.txt, this is the case when image_size
	 * is non-zero (practically speaking, since v3.17).
	 */
	h = (struct arm64_image_header *)kernel;
	if (!h->image_size) {
	pr_info("BHUPESH, 1b, Inside %s\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	/* Check cpu features */
	flags = le64_to_cpu(h->flags);
	be_image = arm64_image_flag_field(flags, ARM64_IMAGE_FLAG_BE);
	be_kernel = IS_ENABLED(CONFIG_CPU_BIG_ENDIAN);
	if ((be_image != be_kernel) && !system_supports_mixed_endian()) {
		pr_info("BHUPESH, 1c, Inside %s\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	value = arm64_image_flag_field(flags, ARM64_IMAGE_FLAG_PAGE_SIZE);
	if (((value == ARM64_IMAGE_FLAG_PAGE_SIZE_4K) &&
			!system_supports_4kb_granule()) ||
	    ((value == ARM64_IMAGE_FLAG_PAGE_SIZE_64K) &&
			!system_supports_64kb_granule()) ||
	    ((value == ARM64_IMAGE_FLAG_PAGE_SIZE_16K) &&
			!system_supports_16kb_granule())) {
		pr_info("BHUPESH, 1d, Inside %s\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	/* Load the kernel */
	kbuf.image = image;
	kbuf.buf_min = 0;
	kbuf.buf_max = ULONG_MAX;
	kbuf.top_down = false;

	kbuf.buffer = kernel;
	kbuf.bufsz = kernel_len;
	kbuf.mem = 0;
	kbuf.memsz = le64_to_cpu(h->image_size);
	text_offset = le64_to_cpu(h->text_offset);
	kbuf.buf_align = MIN_KIMG_ALIGN;

	/* Adjust kernel segment with TEXT_OFFSET */
	kbuf.memsz += text_offset;

	ret = kexec_add_buffer(&kbuf);
	if (ret) {
		pr_info("BHUPESH, 1e, Inside %s, ret=%d\n", __func__,
			ret);
		return ERR_PTR(ret);
	}

	kernel_segment = &image->segment[image->nr_segments - 1];
	kernel_segment->mem += text_offset;
	kernel_segment->memsz -= text_offset;
	image->start = kernel_segment->mem;

	pr_info("Loaded kernel at 0x%lx bufsz=0x%lx memsz=0x%lx\n",
				kernel_segment->mem, kbuf.bufsz,
				kernel_segment->memsz);

	/* Load additional data */
	ret = load_other_segments(image,
				kernel_segment->mem, kernel_segment->memsz,
				initrd, initrd_len, cmdline);

	pr_info("BHUPESH, 1f, Inside %s, ret=%d\n", __func__, ret);
	return ERR_PTR(ret);
}

#ifdef CONFIG_KEXEC_IMAGE_VERIFY_SIG
static int image_verify_sig(const char *kernel, unsigned long kernel_len)
{
	return verify_pefile_signature(kernel, kernel_len, NULL,
				       VERIFYING_KEXEC_PE_SIGNATURE);
}
#endif

const struct kexec_file_ops kexec_image_ops = {
	.probe = image_probe,
	.load = image_load,
#ifdef CONFIG_KEXEC_IMAGE_VERIFY_SIG
	.verify_sig = image_verify_sig,
#endif
};
