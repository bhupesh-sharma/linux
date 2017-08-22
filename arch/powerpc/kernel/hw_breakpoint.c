/*
 * HW_breakpoint: a unified kernel/user-space hardware breakpoint facility,
 * using the CPU's debug registers. Derived from
 * "arch/x86/kernel/hw_breakpoint.c"
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright 2010 IBM Corporation
 * Author: K.Prasad <prasad@linux.vnet.ibm.com>
 *
 */

#include <linux/hw_breakpoint.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/percpu.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp.h>

#include <asm/hw_breakpoint.h>
#include <asm/processor.h>
#include <asm/sstep.h>
#include <linux/uaccess.h>

//#define printk(fmt, ...) (0)
/*
 * Stores the breakpoints currently in use on each breakpoint address
 * register for every cpu
 */
static DEFINE_PER_CPU(struct perf_event *, bp_per_reg);

/*
 * Returns total number of data or instruction breakpoints available.
 */
int hw_breakpoint_slots(int type)
{
	return HBP_NUM;
}

/*
 * Install a perf counter breakpoint.
 *
 * We seek a free debug address register and use it for this
 * breakpoint.
 *
 * Atomic: we hold the counter->ctx->lock and we only handle variables
 * and registers local to this cpu.
 */
int arch_install_hw_breakpoint(struct perf_event *bp)
{
	//printk("BHUPESH arch_install_hw_breakpoint, %s\n", __func__);
	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
	struct perf_event **slot = this_cpu_ptr(&bp_per_reg);

	*slot = bp;

	if (!(bp->attr.bp_type & HW_BREAKPOINT_X)) {
		/*
		 * Do not install DABR values if the instruction must be single-stepped.
		 * If so, DABR will be populated in single_step_dabr_instruction().
		 */
		if (current->thread.last_hit_ubp != bp)
			__set_breakpoint(info);
	} else {
		//printk("BHUPESH arch_install_hw_breakpoint calling ciabr with info->address=%lu, %s\n", info->address, __func__);
		__set_breakpoint_ciabr(info);
	}

	return 0;
}

/*
 * Uninstall the breakpoint contained in the given counter.
 *
 * First we search the debug address register it uses and then we disable
 * it.
 *
 * Atomic: we hold the counter->ctx->lock and we only handle variables
 * and registers local to this cpu.
 */
void arch_uninstall_hw_breakpoint(struct perf_event *bp)
{
	struct perf_event **slot = this_cpu_ptr(&bp_per_reg);

	if (*slot != bp) {
		WARN_ONCE(1, "Can't find the breakpoint");
		return;
	}

	*slot = NULL;
	hw_breakpoint_disable();
}

/*
 * Perform cleanup of arch-specific counters during unregistration
 * of the perf-event
 */
void arch_unregister_hw_breakpoint(struct perf_event *bp)
{
	/*
	 * If the breakpoint is unregistered between a hw_breakpoint_handler()
	 * and the single_step_dabr_instruction(), then cleanup the breakpoint
	 * restoration variables to prevent dangling pointers.
	 * FIXME, this should not be using bp->ctx at all! Sayeth peterz.
	 */
	if (bp->ctx && bp->ctx->task && bp->ctx->task != ((void *)-1L))
		bp->ctx->task->thread.last_hit_ubp = NULL;
}

/*
 * Check for virtual address in kernel space.
 */
int arch_check_bp_in_kernelspace(struct perf_event *bp)
{
	//printk("BHUPESH inside arch_check_bp_in_kernelspace, %s\n", __func__);
	struct arch_hw_breakpoint *info = counter_arch_bp(bp);

	return is_kernel_addr(info->address);
}

int arch_bp_generic_fields(int type, int *gen_bp_type)
{
	//printk("BHUPESH inside arch_bp_generic_fields, %s\n", __func__);
	*gen_bp_type = 0;
	if (type & HW_BRK_TYPE_READ)
		*gen_bp_type |= HW_BREAKPOINT_R;
	if (type & HW_BRK_TYPE_WRITE)
		*gen_bp_type |= HW_BREAKPOINT_W;
	if (*gen_bp_type == 0)
		return -EINVAL;
	return 0;
}

/*
 * Validate the arch-specific HW Breakpoint register settings
 */
int arch_validate_hwbkpt_settings(struct perf_event *bp)
{
	int ret = -EINVAL, length_max;
	struct arch_hw_breakpoint *info = counter_arch_bp(bp);

	//printk("BHUPESH inside arch validate hwbkpt settings 1, %s\n", __func__);
	if (!bp)
		return ret;

	info->type = HW_BRK_TYPE_TRANSLATE;
	//printk("BHUPESH inside arch validate hwbkpt settings 2, bp->attr.bp_type=0x%x, %s\n", bp->attr.bp_type, __func__);
	if (bp->attr.bp_type & HW_BREAKPOINT_R)
		info->type |= HW_BRK_TYPE_READ;
	if (bp->attr.bp_type & HW_BREAKPOINT_W)
		info->type |= HW_BRK_TYPE_WRITE;
	if (bp->attr.bp_type & HW_BREAKPOINT_X)
		info->type |= HW_BRK_TYPE_CIABR_MATCH_PRIV;
	if (info->type == HW_BRK_TYPE_TRANSLATE) {
		//printk("BHUPESH inside arch validate hwbkpt settings 2a, bp->attr.bp_type=0x%x, %s\n", bp->attr.bp_type, __func__);
		/* must set alteast read or write */
		return ret;
	}

	//printk("BHUPESH inside arch validate hwbkpt settings 3, %s\n", __func__);
	if (!(bp->attr.exclude_user))
		info->type |= HW_BRK_TYPE_USER;
	if (!(bp->attr.exclude_kernel))
		info->type |= HW_BRK_TYPE_KERNEL;
	if (!(bp->attr.exclude_hv))
		info->type |= HW_BRK_TYPE_HYP;
	info->address = bp->attr.bp_addr;
	info->len = bp->attr.bp_len;

	//printk("BHUPESH inside arch validate hwbkpt settings 4, %s\n", __func__);
	
	if (!(bp->attr.bp_type & HW_BREAKPOINT_X)) {
		/*
		 * Since breakpoint length can be a maximum of HW_BREAKPOINT_LEN(8)
		 * and breakpoint addresses are aligned to nearest double-word
		 * HW_BREAKPOINT_ALIGN by rounding off to the lower address, the
		 * 'symbolsize' should satisfy the check below.
		 */
		length_max = 8; /* DABR */
		if (cpu_has_feature(CPU_FTR_DAWR)) {
			length_max = 512 ; /* 64 doublewords */
			/* DAWR region can't cross 512 boundary */
			if ((bp->attr.bp_addr >> 10) != 
					((bp->attr.bp_addr + bp->attr.bp_len - 1) >> 10))
				return -EINVAL;
		}
		if (info->len >
				(length_max - (info->address & HW_BREAKPOINT_ALIGN)))
			return -EINVAL;
	}
	
	//printk("BHUPESH inside arch validate hwbkpt settings 5, %s\n", __func__);
	return 0;
}

/*
 * Restores the breakpoint on the debug registers.
 * Invoke this function if it is known that the execution context is
 * about to change to cause loss of MSR_SE settings.
 */
void thread_change_pc(struct task_struct *tsk, struct pt_regs *regs)
{
	struct arch_hw_breakpoint *info;

	if (likely(!tsk->thread.last_hit_ubp))
		return;

	info = counter_arch_bp(tsk->thread.last_hit_ubp);
	regs->msr &= ~MSR_SE;
	__set_breakpoint(info);
	tsk->thread.last_hit_ubp = NULL;
}

/*
 * Handle debug exception notifications.
 */
int hw_breakpoint_handler(struct die_args *args)
{
	int rc = NOTIFY_STOP;
	struct perf_event *bp;
	struct pt_regs *regs = args->regs;
#ifndef CONFIG_PPC_8xx
	int stepped = 1;
	unsigned int instr;
#endif
	struct arch_hw_breakpoint *info;
	unsigned long dar = regs->dar;

	//printk("BHUPESH hw_breakpoint_handler 1 inside %s\n", __func__);
	/* Disable breakpoints during exception handling */
	hw_breakpoint_disable();

	/*
	 * The counter may be concurrently released but that can only
	 * occur from a call_rcu() path. We can then safely fetch
	 * the breakpoint, use its callback, touch its counter
	 * while we are in an rcu_read_lock() path.
	 */
	rcu_read_lock();

	bp = __this_cpu_read(bp_per_reg);
	if (!bp) {
		rc = NOTIFY_DONE;
		goto out;
	}
	info = counter_arch_bp(bp);

	//printk("BHUPESH hw_breakpoint_handler 2 inside %s\n", __func__);
	/*
	 * Return early after invoking user-callback function without restoring
	 * DABR if the breakpoint is from ptrace which always operates in
	 * one-shot mode. The ptrace-ed process will receive the SIGTRAP signal
	 * generated in do_dabr().
	 */
	if (bp->overflow_handler == ptrace_triggered) {
		perf_bp_event(bp, regs);
		rc = NOTIFY_DONE;
		goto out;
	}

	//printk("BHUPESH hw_breakpoint_handler 3 inside %s\n", __func__);
	/*
	 * Verify if dar lies within the address range occupied by the symbol
	 * being watched to filter extraneous exceptions.  If it doesn't,
	 * we still need to single-step the instruction, but we don't
	 * generate an event.
	 */
	info->type &= ~HW_BRK_TYPE_EXTRANEOUS_IRQ;
	if (!((bp->attr.bp_addr <= dar) &&
	      (dar - bp->attr.bp_addr < bp->attr.bp_len)))
		info->type |= HW_BRK_TYPE_EXTRANEOUS_IRQ;

	//printk("BHUPESH hw_breakpoint_handler 4 inside %s\n", __func__);
#ifndef CONFIG_PPC_8xx
	/* Do not emulate user-space instructions, instead single-step them */
	if (user_mode(regs)) {
		current->thread.last_hit_ubp = bp;
		regs->msr |= MSR_SE;
		goto out;
	}

	//printk("BHUPESH hw_breakpoint_handler 5 inside %s\n", __func__);
	stepped = 0;
	instr = 0;
	if (!__get_user_inatomic(instr, (unsigned int *) regs->nip))
		stepped = emulate_step(regs, instr);

	//printk("BHUPESH hw_breakpoint_handler 6 inside %s\n", __func__);
	/*
	 * emulate_step() could not execute it. We've failed in reliably
	 * handling the hw-breakpoint. Unregister it and throw a warning
	 * message to let the user know about it.
	 */
	if (!stepped) {
		WARN(1, "Unable to handle hardware breakpoint. Breakpoint at "
			"0x%lx will be disabled.", info->address);
		perf_event_disable_inatomic(bp);
		goto out;
	}
	//printk("BHUPESH hw_breakpoint_handler 7 inside %s\n", __func__);
#endif
	/*
	 * As a policy, the callback is invoked in a 'trigger-after-execute'
	 * fashion
	 */
	if (!(info->type & HW_BRK_TYPE_EXTRANEOUS_IRQ))
		perf_bp_event(bp, regs);

	//printk("BHUPESH hw_breakpoint_handler 8 inside %s\n", __func__);
	__set_breakpoint(info);
	//printk("BHUPESH hw_breakpoint_handler 9 inside %s\n", __func__);
out:
	rcu_read_unlock();
	//printk("BHUPESH hw_breakpoint_handler 10 inside %s\n", __func__);
	return rc;
}
NOKPROBE_SYMBOL(hw_breakpoint_handler);

/*
 * Handle single-step exceptions following a DABR hit.
 */
static int single_step_dabr_instruction(struct die_args *args)
{
	struct pt_regs *regs = args->regs;
	struct perf_event *bp = NULL;
	struct arch_hw_breakpoint *info;

	bp = current->thread.last_hit_ubp;
	/*
	 * Check if we are single-stepping as a result of a
	 * previous HW Breakpoint exception
	 */
	if (!bp)
		return NOTIFY_DONE;

	info = counter_arch_bp(bp);

	/*
	 * We shall invoke the user-defined callback function in the single
	 * stepping handler to confirm to 'trigger-after-execute' semantics
	 */
	if (!(info->type & HW_BRK_TYPE_EXTRANEOUS_IRQ))
		perf_bp_event(bp, regs);

	__set_breakpoint(info);
	current->thread.last_hit_ubp = NULL;

	/*
	 * If the process was being single-stepped by ptrace, let the
	 * other single-step actions occur (e.g. generate SIGTRAP).
	 */
	if (test_thread_flag(TIF_SINGLESTEP))
		return NOTIFY_DONE;

	return NOTIFY_STOP;
}
NOKPROBE_SYMBOL(single_step_dabr_instruction);

/*
 * Handle single-step exceptions following a IABR hit.
 */
static int single_step_iabr_instruction(struct die_args *args)
{
	struct pt_regs *regs = args->regs;
	struct perf_event *bp = NULL;
	struct arch_hw_breakpoint *info;

	bp = current->thread.last_hit_ubp;
	/*
	 * Check if we are single-stepping as a result of a
	 * previous HW Breakpoint exception
	 */
	if (!bp)
		return NOTIFY_DONE;

	info = counter_arch_bp(bp);

	/*
	 * We shall invoke the user-defined callback function in the single
	 * stepping handler to confirm to 'trigger-after-execute' semantics
	 */
	if (!(info->type & HW_BRK_TYPE_EXTRANEOUS_IRQ))
		perf_bp_event(bp, regs);

	__set_breakpoint_ciabr(info);
	current->thread.last_hit_ubp = NULL;

	/*
	 * If the process was being single-stepped by ptrace, let the
	 * other single-step actions occur (e.g. generate SIGTRAP).
	 */
	if (test_thread_flag(TIF_SINGLESTEP))
		return NOTIFY_DONE;

	return NOTIFY_STOP;
}
NOKPROBE_SYMBOL(single_step_iabr_instruction);

static int single_step_instruction(struct die_args *args)
{
	int rc = NOTIFY_STOP;
	struct perf_event *bp = NULL;

	bp = current->thread.last_hit_ubp;
	printk("BHUPESH single_step_instruction inside %s, bp=%p\n", __func__, bp);
	/*
	 * Check if we are single-stepping as a result of a
	 * previous HW Breakpoint exception
	 */
	if (!bp)
		return NOTIFY_DONE;


	/*
	 * Check if we are handling a DABR or IABR
	 */
	if (bp->attr.bp_type & HW_BREAKPOINT_R) {
		rc = single_step_dabr_instruction(args);
		printk("BHUPESH single_step_instruction 1 inside %s\n", __func__);
	}
	
	if (bp->attr.bp_type & HW_BREAKPOINT_X) {
		rc = single_step_iabr_instruction(args);
		printk("BHUPESH single_step_instruction 2 inside %s\n", __func__);
	}

	return rc;
}
NOKPROBE_SYMBOL(single_step_instruction);

/*
 * Handle debug exception notifications.
 */
int hw_breakpoint_exceptions_notify(
		struct notifier_block *unused, unsigned long val, void *data)
{
	int ret = NOTIFY_DONE;

	printk("BHUPESH hw_breakpoint_exceptions_notify, inside %s\n", __func__);
	switch (val) {
	case DIE_DABR_MATCH:
		printk("BHUPESH hw_breakpoint_exceptions_notify DABR inside %s\n", __func__);
		ret = hw_breakpoint_handler(data);
		break;
	case DIE_SSTEP:
		printk("BHUPESH hw_breakpoint_exceptions_notify SSTEP inside %s\n", __func__);
		ret = single_step_instruction(data);
		break;
	case DIE_IABR_MATCH:
		printk("BHUPESH hw_breakpoint_exceptions_notify IABR inside %s\n", __func__);
		WARN_ON(val==DIE_IABR_MATCH);
		break;
	}

	return ret;
}
NOKPROBE_SYMBOL(hw_breakpoint_exceptions_notify);

/*
 * Release the user breakpoints used by ptrace
 */
void flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	struct thread_struct *t = &tsk->thread;

	//printk("BHUPESH inside flush_ptrace_hw_breakpoint, %s\n", __func__);
	unregister_hw_breakpoint(t->ptrace_bps[0]);
	t->ptrace_bps[0] = NULL;
}

void hw_breakpoint_pmu_read(struct perf_event *bp)
{
	/* TODO */
}
