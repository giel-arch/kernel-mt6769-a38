#ifndef _MT_PLAT_AEE_H
#define _MT_PLAT_AEE_H

#include <linux/bug.h>
#include <linux/printk.h>

#define DB_OPT_DEFAULT	0
#define DB_OPT_FTRACE	0
#define DBG_AEED_NAME	"MTK_AEE"

#ifndef aee_kernel_warning_api
#define aee_kernel_warning_api(file, line, opt, name, fmt, ...) \
	pr_warn("%s:%d: [%s] " fmt, file, line, name, ##__VA_ARGS__)
#endif

#endif /* _MT_PLAT_AEE_H */
