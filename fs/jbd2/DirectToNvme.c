#include <linux/nvme_ioctl.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/bitops.h>
#include <trace/events/jbd2.h>

void DTN_commit(block_device *bdev      ,unsigned int t_tid)
{
	struct nvme_user_io cmd = {
		/*使用一个新的opcode*/
		.opcode = 0x03,
		/*借助reftag来传递t_tid，在底层，只要检测到opcode == 0x03,
		* 则只要通过reftag字段的地址[58:61]Byte取到这个t_tid*/
		.reftag = t_tid,
	};	
	bdev->bd_disk->fops->ioctl(bh->b_bdev ,666 ,
				NVME_IOCTL_SUBMIT_IO ,&cmd);
}

void DTN_write(buffer_head bh ,unsigned int t_tid)
{
	bh->t_tid = t_tid;
	submit_bh(REQ_OP_WRITE, REQ_SYNC, bh);
}

