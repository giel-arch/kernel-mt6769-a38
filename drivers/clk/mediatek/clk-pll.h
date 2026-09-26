#ifndef __CLK_PLL_H_WRAPPER
#define __CLK_PLL_H_WRAPPER

/* 
 * The OPPO OOT clock framework merged the contents of clk-pll.h into clk-mtk.h.
 * To maintain compatibility with mainline files (like clk-fhctl.c, etc) that 
 * still include "clk-pll.h", we just forward the inclusion to clk-mtk.h here.
 */
#include "clk-mtk.h"

#endif /* __CLK_PLL_H_WRAPPER */
