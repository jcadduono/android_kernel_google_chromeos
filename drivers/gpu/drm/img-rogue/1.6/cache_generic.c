/*************************************************************************/ /*!
@File           cache_generic.c
@Title          CPU generic cache management
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@Description    Implements server side code for CPU cache management in a
                CPU agnostic manner.
@License        Dual MIT/GPLv2

The contents of this file are subject to the MIT license as set out below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

Alternatively, the contents of this file may be used under the terms of
the GNU General Public License Version 2 ("GPL") in which case the provisions
of GPL are applicable instead of those above.

If you wish to allow use of your version of this file only under the terms of
GPL, and not to allow others to use your version of this file under the terms
of the MIT license, indicate your decision by deleting the provisions above
and replace them with the notice and other provisions required by GPL as set
out in the file called "GPL-COPYING" included in this distribution. If you do
not delete the provisions above, a recipient may use your version of this file
under the terms of either the MIT license or GPL.

This License is also included in this distribution in the file called
"MIT-COPYING".

EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ /**************************************************************************/
#include "cache_generic.h"
#include "cache_internal.h"
#include "device.h"
#include "pvr_debug.h"
#include "pvrsrv.h"
#include "osfunc.h"
#include "pmr.h"

#if defined(SUPPORT_RANGEBASED_CACHEFLUSH)
//#define CACHEOP_NO_CACHE_LINE_ALIGNED_ROUNDING
static IMG_UINT32 guiCacheLineSize = 0;

/* Perform requested CacheOp on the CPU data cache for successive cache
   line worth of bytes up to page or in-page cache-line boundary */
static INLINE void CacheOpCPURangeBased (PVRSRV_CACHE_OP uiCacheOp,
										 IMG_BYTE *pbCpuVirtAddr,
										 IMG_CPU_PHYADDR sCpuPhyAddr,
										 IMG_DEVMEM_OFFSET_T uiPgAlignedOffset,
										 IMG_DEVMEM_OFFSET_T uiCLAlignedStartOffset,
										 IMG_DEVMEM_OFFSET_T uiCLAlignedEndOffset)
{
	IMG_BYTE *pbCpuVirtAddrEnd;
	IMG_BYTE *pbCpuVirtAddrStart;
	IMG_CPU_PHYADDR sCpuPhyAddrEnd;
	IMG_CPU_PHYADDR sCpuPhyAddrStart;
	IMG_DEVMEM_SIZE_T uiNextPgAlignedOffset;
	IMG_DEVMEM_OFFSET_T uiRelFlushOffset = 0;
	size_t OS_PAGE_SIZE = OSGetPageSize();
	IMG_DEVMEM_SIZE_T uiRelFlushSize = (IMG_DEVMEM_SIZE_T)OS_PAGE_SIZE;

	/* These quantities allows us to perform cache operations
	   at cache-line granularity thereby ensuring we do not
	   perform more than is necessary */
	PVR_ASSERT(uiPgAlignedOffset < uiCLAlignedEndOffset);

	if (uiCLAlignedStartOffset > uiPgAlignedOffset)
	{
		/* Zero unless initially starting at an in-page offset */
		uiRelFlushOffset = uiCLAlignedStartOffset - uiPgAlignedOffset;
		uiRelFlushSize -= uiRelFlushOffset;
	}

	/* uiRelFlushSize is OS_PAGE_SIZE unless current outstanding CacheOp
	   size is smaller. The 1st case handles in-page CacheOp range and
	   the 2nd case handles multiple-page CacheOp range with a last
	   CacheOp size that is less than OS_PAGE_SIZE */
	uiNextPgAlignedOffset = uiPgAlignedOffset + (IMG_DEVMEM_SIZE_T)OS_PAGE_SIZE;
	if (uiNextPgAlignedOffset < uiPgAlignedOffset)
	{
		/* uiNextPgAlignedOffset is greater than uiCLAlignedEndOffset
		   by implication of this wrap-round; this only happens when
		   uiPgAlignedOffset is the last page aligned offset */
		uiRelFlushSize = uiRelFlushOffset ?
				uiCLAlignedEndOffset - uiCLAlignedStartOffset :
				uiCLAlignedEndOffset - uiPgAlignedOffset;
	}
	else
	{
		if (uiNextPgAlignedOffset > uiCLAlignedEndOffset)
		{
			uiRelFlushSize = uiRelFlushOffset ?
					uiCLAlignedEndOffset - uiCLAlignedStartOffset :
					uiCLAlignedEndOffset - uiPgAlignedOffset;
		}
	}

	/* More efficient to request cache maintenance operation for full
	   relative range as opposed to multiple cache-aligned ranges */
	pbCpuVirtAddrStart = pbCpuVirtAddr + uiRelFlushOffset;
	pbCpuVirtAddrEnd = pbCpuVirtAddrStart + uiRelFlushSize;
	sCpuPhyAddrStart.uiAddr = sCpuPhyAddr.uiAddr + uiRelFlushOffset;
	sCpuPhyAddrEnd.uiAddr = sCpuPhyAddrStart.uiAddr + uiRelFlushSize;

	switch (uiCacheOp)
	{
		case PVRSRV_CACHE_OP_CLEAN:
			OSCleanCPUCacheRangeKM(pbCpuVirtAddrStart, pbCpuVirtAddrEnd,
									sCpuPhyAddrStart, sCpuPhyAddrEnd);
			break;
		case PVRSRV_CACHE_OP_INVALIDATE:
			OSInvalidateCPUCacheRangeKM(pbCpuVirtAddrStart, pbCpuVirtAddrEnd,
									sCpuPhyAddrStart, sCpuPhyAddrEnd);
			break;
		case PVRSRV_CACHE_OP_FLUSH:
			OSFlushCPUCacheRangeKM(pbCpuVirtAddrStart, pbCpuVirtAddrEnd,
									sCpuPhyAddrStart, sCpuPhyAddrEnd);
			break;
		default:
			PVR_DPF((PVR_DBG_ERROR,	"%s: Invalid cache operation type %d",
					__FUNCTION__, uiCacheOp));
			PVR_ASSERT(0);
			break;
	}
}

/* This function assumes buffer backing PMR data for CacheOp range is valid */
static INLINE PVRSRV_ERROR CacheOpRangeBasedSlow (PMR *psPMR,
												  IMG_BOOL bPMRIsSparse,
												  PVRSRV_CACHE_OP uiCacheOp,
												  IMG_UINT32 ui32NumOfPages,
												  IMG_CPU_PHYADDR *psCpuPhyAddr,
												  IMG_BOOL *pbCpuPhyAddrValid,
												  IMG_DEVMEM_OFFSET_T uiPgAlignedStartOffset,
												  IMG_DEVMEM_OFFSET_T uiPgAlignedEndOffset,
												  IMG_DEVMEM_OFFSET_T uiCLAlignedStartOffset,
												  IMG_DEVMEM_OFFSET_T uiCLAlignedEndOffset)
{
	IMG_HANDLE hPrivOut;
	IMG_UINT32 ui32PageIndex;
	IMG_DEVMEM_SIZE_T uiOutSize;
	IMG_UINT32 ui32KMapNumOfPages;
	IMG_BYTE *pbCpuVirtAddr = NULL;
	PVRSRV_ERROR eError = PVRSRV_OK;
	IMG_UINT32 ui32KMapNumOfPagesSize;
	IMG_DEVMEM_OFFSET_T uiPgAlignedOffsetNext;
	IMG_UINT32 OS_PAGE_SHIFT = (IMG_UINT32)OSGetPageShift();
	size_t OS_PAGE_SIZE = OSGetPageSize();

	/* Start with expectation of acquiring PMR kernel mapping data in
	   PMR_MAX_TRANSLATION_STACK_ALLOC or ui32NumOfPages number of pages
	   per iteration however this may not always be possible; on failure
	   down size the expectation by 2 until it degenerates to 1 at which
	   point we completely fail the CacheOp request and bail out */
	ui32KMapNumOfPages = ui32NumOfPages > PMR_MAX_TRANSLATION_STACK_ALLOC ?
				PMR_MAX_TRANSLATION_STACK_ALLOC : ui32NumOfPages;
	ui32KMapNumOfPagesSize = ui32KMapNumOfPages << OS_PAGE_SHIFT;
	ui32PageIndex = ui32KMapNumOfPages;

	for (uiPgAlignedOffsetNext = uiPgAlignedStartOffset;
		 uiPgAlignedOffsetNext < uiPgAlignedEndOffset;
		 uiPgAlignedOffsetNext += (IMG_DEVMEM_SIZE_T)OS_PAGE_SIZE, pbCpuVirtAddr += OS_PAGE_SIZE)
	{
		IMG_BOOL bRetry = IMG_TRUE;

		if (ui32PageIndex < ui32KMapNumOfPages)
		{
			if (pbCpuPhyAddrValid[ui32PageIndex])
			{
				/* Perform actual CPU CacheOp */
				CacheOpCPURangeBased(uiCacheOp,
									 pbCpuVirtAddr,
									 psCpuPhyAddr[ui32PageIndex],
									 uiPgAlignedOffsetNext,
									 uiCLAlignedStartOffset,
									 uiCLAlignedEndOffset);
			}
		}
		else
		{
			/* At each ui32KMapNumOfPages number of pages boundary
			   we look-up the PMR CPU physical addresses and kmap
			   the CPU virtual range; the rationale here is to
			   lower number of calls to the PMR framework */
			while(bRetry == IMG_TRUE)
			{
				eError = PMR_CpuPhysAddr(psPMR,
										 OS_PAGE_SHIFT,
										 ui32KMapNumOfPages,
										 uiPgAlignedOffsetNext,
										 psCpuPhyAddr,
										 pbCpuPhyAddrValid);
				if (eError != PVRSRV_OK)
				{
					if (ui32KMapNumOfPages > 1)
					{
						ui32KMapNumOfPagesSize >>= 1;
						ui32KMapNumOfPages >>= 1;
					}
					else
					{
						PVR_ASSERT(0);
						goto e0;
					}
				}
				else
				{
					if (bPMRIsSparse)
					{
						eError =
							PMRAcquireSparseKernelMappingData(psPMR,
															  uiPgAlignedOffsetNext,
															  ui32KMapNumOfPagesSize,
															  (void **)&pbCpuVirtAddr,
															  (size_t*)&uiOutSize,
															  &hPrivOut);
					}
					else
					{
						eError =
							PMRAcquireKernelMappingData(psPMR,
														uiPgAlignedOffsetNext,
														ui32KMapNumOfPagesSize,
														(void **)&pbCpuVirtAddr,
														(size_t*)&uiOutSize,
														&hPrivOut);
					}

					if (eError != PVRSRV_OK)
					{
						if (ui32KMapNumOfPages > 1)
						{
							ui32KMapNumOfPagesSize >>= 1;
							ui32KMapNumOfPages >>= 1;
						}
						else
						{
							PVR_ASSERT(0);
							goto e0;
						}
					}
					else
					{
						/* Setup OK, exit loop */
						bRetry = IMG_FALSE;
					}
				}
			}

			ui32PageIndex = 0;
			if (pbCpuPhyAddrValid[ui32PageIndex])
			{
				/* Perform actual CPU CacheOp */
				CacheOpCPURangeBased(uiCacheOp,
									 pbCpuVirtAddr,
									 psCpuPhyAddr[ui32PageIndex],
									 uiPgAlignedOffsetNext,
									 uiCLAlignedStartOffset,
									 uiCLAlignedEndOffset);
			}
		}

		if (++ui32PageIndex >= ui32KMapNumOfPages)
		{
			PVR_ASSERT(ui32PageIndex == ui32KMapNumOfPages);

			/* Drop kernel mapping data here for completed batch */
			eError = PMRReleaseKernelMappingData(psPMR, hPrivOut);
			PVR_ASSERT(eError == PVRSRV_OK);

			/* Less the just completed batch */
			ui32NumOfPages -= ui32KMapNumOfPages;
			if (! ui32NumOfPages)
			{
				break;
			}
			else
			{
				if (ui32NumOfPages < ui32KMapNumOfPages)
				{
					ui32KMapNumOfPages = ui32NumOfPages;
					ui32KMapNumOfPagesSize = ui32KMapNumOfPages << OS_PAGE_SHIFT;
				}
			}
		}
	}

e0:
	return eError;
}

/* This function assumes underlying PMR data for CacheOp range is valid */
static INLINE PVRSRV_ERROR CacheOpRangeBasedFast (PVRSRV_CACHE_OP uiCacheOp,
												  IMG_BYTE *pbCpuVirtAddr,
												  IMG_CPU_PHYADDR *psCpuPhyAddr,
												  IMG_BOOL *pbCpuPhyAddrValid,
												  IMG_DEVMEM_OFFSET_T uiPgAlignedStartOffset,
												  IMG_DEVMEM_OFFSET_T uiPgAlignedEndOffset,
												  IMG_DEVMEM_OFFSET_T uiCLAlignedStartOffset,
												  IMG_DEVMEM_OFFSET_T uiCLAlignedEndOffset)
{
	IMG_UINT32 ui32PageIndex;
	IMG_BYTE *pbCpuVirtAddrNext;
	IMG_DEVMEM_OFFSET_T uiPgAlignedOffsetNext;
	size_t OS_PAGE_SIZE = OSGetPageSize();

	for (uiPgAlignedOffsetNext = uiPgAlignedStartOffset, pbCpuVirtAddrNext = pbCpuVirtAddr, ui32PageIndex = 0;
		 uiPgAlignedOffsetNext < uiPgAlignedEndOffset;
		 uiPgAlignedOffsetNext += (IMG_DEVMEM_SIZE_T)OS_PAGE_SIZE, pbCpuVirtAddrNext += OS_PAGE_SIZE, ui32PageIndex += 1)
	{
		if (pbCpuPhyAddrValid[ui32PageIndex])
		{
			/* Perform actual CPU CacheOp */
			CacheOpCPURangeBased(uiCacheOp,
								 pbCpuVirtAddrNext,
								 psCpuPhyAddr[ui32PageIndex],
								 uiPgAlignedOffsetNext,
								 uiCLAlignedStartOffset,
								 uiCLAlignedEndOffset);
		}
	}

	return PVRSRV_OK;
}

PVRSRV_ERROR CacheOpQueue(PMR *psPMR,
						  IMG_DEVMEM_OFFSET_T uiOffset,
						  IMG_DEVMEM_SIZE_T uiSize,
						  PVRSRV_CACHE_OP uiCacheOp)
{
	IMG_BOOL *pbValid;
	IMG_HANDLE hPrivOut;
	IMG_BOOL bPMRIsSparse;
	IMG_INT32 ui32NumOfPages;
	IMG_DEVMEM_SIZE_T uiOutSize;
	IMG_BYTE *pbCpuVirtAddr = NULL;
	IMG_DEVMEM_SIZE_T uiPgAlignedSize;
	IMG_BOOL bPMRKMapDataIsPreacquired;
	IMG_CPU_PHYADDR *psCpuPhyAddr = NULL;
	IMG_DEVMEM_OFFSET_T uiCLAlignedEndOffset;
	IMG_DEVMEM_OFFSET_T uiPgAlignedEndOffset;
	IMG_DEVMEM_OFFSET_T uiCLAlignedStartOffset;
	IMG_DEVMEM_OFFSET_T uiPgAlignedStartOffset;
	IMG_BOOL bPMRDataIsUsingStackAlloc = IMG_TRUE;
	IMG_BOOL abValid[PMR_MAX_TRANSLATION_STACK_ALLOC];
	IMG_CPU_PHYADDR asCpuPhyAddr[PMR_MAX_TRANSLATION_STACK_ALLOC];
	IMG_UINT32 OS_PAGE_SHIFT = (IMG_UINT32)OSGetPageShift();
	size_t OS_PAGE_SIZE = OSGetPageSize();
	PVRSRV_ERROR eError = PVRSRV_OK;

	if (uiCacheOp == PVRSRV_CACHE_OP_NONE)
	{
		PVR_ASSERT(0);
		return eError;
	}
	else
	{
		/* Carry out full dcache operation if size (in pages) qualifies */
		if ((uiSize >> OS_PAGE_SHIFT) >= PVR_DIRTY_PAGECOUNT_FLUSH_THRESHOLD)
		{
			eError = OSCPUOperation(PVRSRV_CACHE_OP_FLUSH);
			if (eError == PVRSRV_OK)
			{
				return PVRSRV_OK;
			}
		}
	}

	if (! guiCacheLineSize)
	{
		guiCacheLineSize = OSCPUCacheAttributeSize(PVR_DCACHE_LINE_SIZE);
		PVR_ASSERT(guiCacheLineSize != 0);
	}

	/* Start with expectation of acquiring
	   full PMR kernel mapping data; this
	   may not always be possible */
	bPMRKMapDataIsPreacquired = IMG_TRUE;

	/* Need this for kernel mapping */
	bPMRIsSparse = PMR_IsSparse(psPMR);

	/* Round the incoming offset down to the nearest cache-line / page aligned address */
	uiCLAlignedEndOffset = uiOffset + uiSize;
	uiCLAlignedEndOffset = PVR_ALIGN(uiCLAlignedEndOffset, (IMG_DEVMEM_SIZE_T)guiCacheLineSize);
	uiCLAlignedStartOffset = (uiOffset & ~((IMG_DEVMEM_SIZE_T)guiCacheLineSize-1));

	uiPgAlignedEndOffset = uiCLAlignedEndOffset;
	uiPgAlignedEndOffset = PVR_ALIGN(uiPgAlignedEndOffset, (IMG_DEVMEM_SIZE_T)OS_PAGE_SIZE);
	uiPgAlignedStartOffset = (uiOffset & ~((IMG_DEVMEM_SIZE_T)OS_PAGE_SIZE-1));
	uiPgAlignedSize = uiPgAlignedEndOffset - uiPgAlignedStartOffset;

#if defined(CACHEOP_NO_CACHE_LINE_ALIGNED_ROUNDING)
	/* For internal debug if cache-line optimised
	   flushing causes data corruption */
	uiCLAlignedStartOffset = uiPgAlignedStartOffset;
	uiCLAlignedEndOffset = uiPgAlignedEndOffset;
#endif

	/* Type of allocation backing the PMR data */
	ui32NumOfPages = uiPgAlignedSize >> OS_PAGE_SHIFT;
	if (ui32NumOfPages > PMR_MAX_TRANSLATION_STACK_ALLOC)
	{
		psCpuPhyAddr = OSAllocZMem(ui32NumOfPages * sizeof(IMG_CPU_PHYADDR));
		if (psCpuPhyAddr != NULL)
		{
			pbValid = OSAllocZMem(ui32NumOfPages * sizeof(IMG_BOOL));
			if (pbValid != NULL)
			{
				bPMRDataIsUsingStackAlloc = IMG_FALSE;
			}
			else
			{
				OSFreeMem(psCpuPhyAddr);
			}
		}
	}

	/* If using stack allocation, point to it */
	if (bPMRDataIsUsingStackAlloc == IMG_TRUE)
	{
		psCpuPhyAddr = asCpuPhyAddr;
		pbValid = abValid;

		if (ui32NumOfPages > PMR_MAX_TRANSLATION_STACK_ALLOC)
		{
			bPMRKMapDataIsPreacquired = IMG_FALSE;
		}
	}

	/* Acquire full kmap data for PMR range */
	if (bPMRKMapDataIsPreacquired == IMG_TRUE)
	{
		eError = PMR_CpuPhysAddr(psPMR,
								 OS_PAGE_SHIFT,
								 ui32NumOfPages,
								 uiPgAlignedStartOffset,
								 psCpuPhyAddr,
								 pbValid);
		if (eError == PVRSRV_OK)
		{
			if (bPMRIsSparse)
			{
				eError = PMRAcquireSparseKernelMappingData(psPMR,
														   uiPgAlignedStartOffset,
														   uiPgAlignedSize,
														   (void **)&pbCpuVirtAddr,
														   (size_t*)&uiOutSize,
														   &hPrivOut);
			}
			else
			{
				eError = PMRAcquireKernelMappingData(psPMR,
													 uiPgAlignedStartOffset,
													 uiPgAlignedSize,
													 (void **)&pbCpuVirtAddr,
													 (size_t*)&uiOutSize,
													 &hPrivOut);
			}
		}

		if (eError != PVRSRV_OK)
		{
			bPMRKMapDataIsPreacquired = IMG_FALSE;
		}
	}

	if (bPMRKMapDataIsPreacquired == IMG_TRUE)
	{
		eError = CacheOpRangeBasedFast (uiCacheOp,
										pbCpuVirtAddr,
										psCpuPhyAddr,
										pbValid,
										uiPgAlignedStartOffset,
										uiPgAlignedEndOffset,
										uiCLAlignedStartOffset,
										uiCLAlignedEndOffset);
		PVR_ASSERT(eError == PVRSRV_OK);

		eError = PMRReleaseKernelMappingData(psPMR, hPrivOut);
		PVR_ASSERT(eError == PVRSRV_OK);
	}
	else
	{
		eError = CacheOpRangeBasedSlow (psPMR,
										bPMRIsSparse,
										uiCacheOp,
										ui32NumOfPages,
										psCpuPhyAddr,
										pbValid,
										uiPgAlignedStartOffset,
										uiPgAlignedEndOffset,
										uiCLAlignedStartOffset,
										uiCLAlignedEndOffset);
		PVR_ASSERT(eError == PVRSRV_OK);
	}

	if (bPMRDataIsUsingStackAlloc == IMG_FALSE)
	{
		if (psCpuPhyAddr != NULL)
		{
			PVR_ASSERT(psCpuPhyAddr != asCpuPhyAddr);
			OSFreeMem(psCpuPhyAddr);
		}

		if (pbValid != NULL)
		{
			PVR_ASSERT(pbValid != abValid);
			OSFreeMem(pbValid);
		}
	}

	return eError;
}
#else
PVRSRV_ERROR CacheOpQueue(PMR *psPMR,
						  IMG_DEVMEM_OFFSET_T uiOffset,
						  IMG_DEVMEM_SIZE_T uiSize,
						  PVRSRV_CACHE_OP uiCacheOp)
{
	PVRSRV_DATA *psData = PVRSRVGetPVRSRVData();
	psData->uiCacheOp = SetCacheOp(psData->uiCacheOp, uiCacheOp);
	return PVRSRV_OK;
}
#endif
