/*
 * (C) Copyright 2012
 * Trustonic
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <common.h>
#include <command.h>
#include "mcimcp.h"
#include "mcinq.h"



#define MC_SMC_N_SIQ	0x4

#if defined(CONFIG_TBASE_ARM_SMC_CALLING_CONVERSION)
#define FC_MASK			(0x80000000)
#define FC_SMC64_MASK	(0x40000000)
#define FC_BASE			(0x3f000000 | FC_MASK | FC_SMC64_MASK )
#define MC_FC_INIT		(FC_BASE + 1)
#define MC_FC_INFO		(FC_BASE + 2)
#else
#define MC_FC_INIT		-1
#define MC_FC_INFO		-2
#endif

/* Don't try to to do more than 50 SIQ tries */
#define MC_MAX_SIQ		50

#define PAGE_SIZE		0x1000
#define PAGE_MASK		0xFFFU

/* <t-base is not yet initialized. FastCall FcInit() has to be used function to set up <t-base.*/
#define MC_STATUS_NOT_INITIALIZED	0
/* Bad parameters have been passed in FcInit(). */
#define MC_STATUS_BAD_INIT			1
/* <t-base did initialize properly. */
#define MC_STATUS_INITIALIZED		2
/* <t-base kernel halted due to an unrecoverable exception. Further information is available extended info */
#define MC_STATUS_HALT				3

#define MCI_SIZE		512
#define TCI_SIZE		4096

#define NQ_NUM_ELEMS	16
#define NQ_LENGTH		280
#define MCP_LENGTH		144

#define MAJOR_VERSION(v)	( v >>16)
#define MINOR_VERSION(v)	(v & 0xffff)

/* Use the arch_extension sec pseudo op before switching to secure world */
#if defined(__GNUC__) && \
	defined(__GNUC_MINOR__) && \
	defined(__GNUC_PATCHLEVEL__) && \
	((__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)) \
	>= 40502 && __GNUC_MINOR__ < 8
#define MC_ARCH_EXTENSION_SEC
#endif



// MCI buffer is one page in size and aligned on a page boundary
static uint8_t mci[MCI_SIZE] __attribute__((aligned(0x1000)));
static uint8_t *nq;
static volatile mcpBuffer_ptr mcp;

struct fc_generic {
	uint32_t cmd;
	uint32_t param[3];
};



static inline long _smc(struct fc_generic *fc)
{
	/* SVC expect values in r0-r3 */
	register u32 reg0 __asm__("r0") = fc->cmd;
	register u32 reg1 __asm__("r1") = fc->param[0];
	register u32 reg2 __asm__("r2") = fc->param[1];
	register u32 reg3 __asm__("r3") = fc->param[2];

	__asm__ volatile (
#ifdef MC_ARCH_EXTENSION_SEC
		/* This pseudo op is supported and required from
		  * binutils 2.21 on */
		".arch_extension sec\n"
#endif
		"smc 0\n"
		: "+r"(reg0), "+r"(reg1), "+r"(reg2), "+r"(reg3)
	);

	/* set response */
	fc->cmd = reg0;
	fc->param[0] = reg1;
	fc->param[1] = reg2;
	fc->param[2] = reg3;
	return reg1;
}

static int mc_nsiq(void)
{
	struct fc_generic nsiq;

	nsiq.cmd = MC_SMC_N_SIQ;
	_smc(&nsiq);

	return nsiq.param[0];
}

static int mc_info(uint32_t ext_info_id, uint32_t *state, uint32_t *ext_info)
{
	int ret = 0;
	struct fc_generic fc_info;

	//Prepare and send t-base INFO command
	memset(&fc_info, 0, sizeof(fc_info));
	fc_info.cmd = MC_FC_INFO;
	fc_info.param[0] = ext_info_id;
	//printf("cmd_getTbaseVersion: send SMC fc_info <- cmd=0x%08x, ext_info_id=0x%08x\n", fc_info.cmd, ext_info_id);
	_smc(&fc_info);

	//printf("cmd_getTbaseVersion: SMC fc_info returned -> r=0x%08x ret=0x%08x state=0x%08x ext_info=0x%08x\n",
	//	  fc_info.cmd,
	//	  fc_info.param[0],
	//	  fc_info.param[1],
	//	  fc_info.param[2]);

	*state  = fc_info.param[1];
	*ext_info = fc_info.param[2];

	return ret;
}

//------------------------------------------------------------------------------
static void put_notification(uint32_t sid)
{
	volatile notificationQueue_t * out = (notificationQueue_t *) nq;

	if ((out->hdr.writeCnt - out->hdr.readCnt) < out->hdr.queueSize) {
		notification_t *not = &out->notification[out->hdr.writeCnt & (out->hdr.queueSize - 1)];
		not->sessionId = sid;
		not->payload = 0;
		out->hdr.writeCnt++;
	}
}


//------------------------------------------------------------------------------
static int32_t get_notification(void)
{
	notification_t *ret = NULL;
	volatile notificationQueue_t *in = (notificationQueue_t *) (nq
					 + sizeof(notificationQueueHeader_t) + NQ_NUM_ELEMS
					 * sizeof(notification_t));

	if ((in->hdr.writeCnt - in->hdr.readCnt) > 0) {
		ret = &(in->notification[in->hdr.readCnt & (in->hdr.queueSize - 1)]);
		in->hdr.readCnt++;
		return ret->sessionId;
	}
	return -1;
}

static int get_tbaseVersion(mcpMessage_ptr msg)
{
	int ret = 0;
	int i;

	msg->cmdGetMobiCoreVersion.cmdHeader.cmdId = MC_MCP_CMD_GET_MOBICORE_VERSION;
	put_notification(0);
    
	for (i = 0; i < MC_MAX_SIQ; i++) {
		mc_nsiq();

		if(get_notification() == 0) {
			break;
		}
	}
    // Check that we have not reach the maximum number of tries.
	if (i == MC_MAX_SIQ) {
		printf("cmd_getTbaseVersion: t-base RTM did not ack the open command!\n");
		ret = -1;
	}

	return ret;
}

static int mci_setup(void)
{
	struct fc_generic fc_init;
	uint32_t mci_offset = 0;
	int i = 0;

	// Initialize MCI
	mci_offset = ((uint32_t)mci) & PAGE_MASK;
	memset(&mci, 0x0, sizeof(mci));

	//Prepare and send t-base INIT command
	fc_init.cmd = MC_FC_INIT;
	// Set MCI as uncached
	fc_init.param[0] = ( virt_to_phys((ulong)mci) | 0x1U);
	fc_init.param[1] = NQ_LENGTH;
	// mcp_offset = 0x118 mcp_length=0x90
	fc_init.param[2] = (NQ_LENGTH<< 16) | MCP_LENGTH;
	_smc(&fc_init);

	if(fc_init.param[0]) {
		printf("cmd_getTbaseVersion: t-base INIT response = %x.\n", fc_init.param[0]);
		printf("cmd_getTbaseVersion: t-base MCI init failed!\n");
		return -1;
	}

	// MCI is setup, do a nsiq to give RTM a chance to run
	for(i = 0; i < MC_MAX_SIQ; i++)  {
		uint32_t state, ext_info;
		mc_nsiq();

		// Read responce and check if initialized
		mc_info(0, &state, &ext_info);
		if(state == MC_STATUS_INITIALIZED) {
			break;
		}
	}
	// Check that we have not reach the maximum number of tries.
	if (i == MC_MAX_SIQ) {
		printf("cmd_getTbaseVersion: t-base RTM failed to initialize.\n");
		return -1;
	}

	// Initialize mcp (buffer on MobiCore communication protocol and notification queue)
	mcp = (mcpBuffer_ptr)((uint8_t*)mci + mci_offset + NQ_LENGTH);
	nq = (uint8_t*)mci + mci_offset;

	return 0;
}

static int mci_unmap(void)
{
	int i;
	mcp->mcpMessage.cmdHeader.cmdId = MC_MCP_CMD_CLOSE_MCP;
	put_notification(0);

	for(i = 0; i < MC_MAX_SIQ; i++)  {
		uint32_t state, ext_info;
		mc_nsiq();

		// Read responce and check if initialized
		mc_info(0, &state, &ext_info);
		if(state != MC_STATUS_INITIALIZED) {
			break;
		}
	}
	// Check that we have not reach the maximum number of tries.
	if (i == MC_MAX_SIQ) {
		printf("cmd_getTbaseVersion: t-base RTM failed to uninitialize!\n");
		return -1;
	}

	return 0;
}

static int do_getTbaseVersion(void)
{
	/* Initialize the <t-base communication interface */
	if(mci_setup())
	{
		printf("cmd_getTbaseVersion: t-base MCI init failed!\n");
		return -1;
	}

	get_tbaseVersion(&mcp->mcpMessage);
	printf("Get t-base info\n");
	printf("    Product ID is: %s\n",mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.productId);
	printf("    MCI version is: %d.%d\n",
	       MAJOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionMci),
	       MINOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionMci));
	printf("    MCLF version is: %d.%d\n",
	       MAJOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionMclf),
	       MINOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionMclf));
	printf("    Container version is: %d.%d\n",
	       MAJOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionContainer),
	       MINOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionContainer));
	printf("    McConfig version is: %d.%d\n",
	       MAJOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionMcConfig),
	       MINOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionMcConfig));
	printf("    TLAPI version is: %d.%d\n",
	       MAJOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionTlApi),
	       MINOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionTlApi));
	printf("    DRAPI version is: %d.%d\n",
	       MAJOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionDrApi),
	       MINOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionDrApi));
	//printf("    CMP version is: %d.%d\n",
	//       MAJOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionCmp),
	//       MINOR_VERSION(mcp->mcpMessage.rspGetMobiCoreVersion.versionInfo.versionCmp));

	/* Unmap <t-base communication interface - otherwise Linux daemon will fail */
	if (mci_unmap())
	{
		printf("cmd_getTbaseVersion: t-base RTM failed to uninitialize!\n");
		return -1;
	}

	return 0;
}

static int doCmd_getTbaseVersion(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	return do_getTbaseVersion();
}

U_BOOT_CMD(
	tbase_version,	CONFIG_SYS_MAXARGS,	1,	doCmd_getTbaseVersion,
	"get tbase version information",
	""
);
