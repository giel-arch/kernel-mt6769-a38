# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_COMMON_CLK_MEDIATEK) += clk-mtk.o clk-pll.o clk-gate.o clk-apmixed.o clk-cpumux.o reset.o clk-mux.o clkchk.o clkdbg.o mtk-pd-chk.o clk-fmeter.o
# obj-$(CONFIG_COMMON_CLK_MEDIATEK_FHCTL) += clk-fhctl.o clk-pllfh.o

# Disabling all other SoC targets because they are incompatible with the OOT clock framework
obj-$(CONFIG_COMMON_CLK_MT6768) += clk-mt6768.o clk-mt6768-pg.o mt6768_clkmgr.o clkchk-mt6768.o clkdbg-mt6768.o mtk-pd-chk-mt6768.o clk-fmeter-mt6768.o
