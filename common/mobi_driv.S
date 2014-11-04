	.section .mobicore_driver,#alloc
	.align 2
	.globl	mobi_drv
mobi_drv:
	.incbin	"../drv.tlbin"
	.globl	mobi_drv_end
mobi_drv_end:

