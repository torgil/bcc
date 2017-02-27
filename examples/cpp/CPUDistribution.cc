/*
 * CPUDistribution Show load distribution across CPU cores during a period of
 *                 time. For Linux, uses BCC, eBPF. Embedded C.
 *
 * Basic example of BCC and kprobes.
 *
 * USAGE: CPUDistribution [duration]
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <unistd.h>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

#include "BPF.h"
#include "shared_table.h"
#include "table_desc.h"
#include "common.h"

const std::string BPF_TABLES = R"(
BPF_TABLE_PUBLIC("hash", pid_t, int, pid_to_cpu, 1024);
BPF_TABLE_PUBLIC("hash", pid_t, uint64_t, pid_to_ts, 1024);
BPF_TABLE_PUBLIC("hash", int, uint64_t, cpu_time, 1024);
)";

const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
BPF_TABLE("extern", pid_t, int, pid_to_cpu, 1024);
BPF_TABLE("extern", pid_t, uint64_t, pid_to_ts, 1024);
BPF_TABLE("extern", int, uint64_t, cpu_time, 1024);
BPF_TABLE("array", int, struct task_struct, tasks, 10);

int task_switch_event(struct pt_regs *ctx, struct task_struct *prev) {
  pid_t prev_pid = prev->pid;
  int* prev_cpu = pid_to_cpu.lookup(&prev_pid);
  uint64_t* prev_ts = pid_to_ts.lookup(&prev_pid);

  pid_t cur_pid = bpf_get_current_pid_tgid();
  int cur_cpu = bpf_get_smp_processor_id();
  uint64_t cur_ts = bpf_ktime_get_ns();

  uint64_t this_cpu_time = 0;
  if (prev_ts) {
    pid_to_ts.delete(&prev_pid);
    this_cpu_time = (cur_ts - *prev_ts);
  }
  if (prev_cpu) {
    pid_to_cpu.delete(&prev_pid);
    if (this_cpu_time > 0) {
      int cpu_key = *prev_cpu;
      uint64_t* history_time = cpu_time.lookup(&cpu_key);
      if (history_time)
        this_cpu_time += *history_time;
      cpu_time.update(&cpu_key, &this_cpu_time);
    }
  }

  pid_to_cpu.update(&cur_pid, &cur_cpu);
  pid_to_ts.update(&cur_pid, &cur_ts);

  return 0;
}
)";

int main(int argc, char** argv) {
  auto ts = ebpf::createSharedTableStorage();
  ebpf::BPF tables(0, &*ts);
  auto init_res = tables.init(BPF_TABLES);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  ebpf::BPF bpf(0, &*ts);
  init_res = bpf.init(BPF_PROGRAM, {"-w"});
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  auto attach_res =
      bpf.attach_kprobe("finish_task_switch", "task_switch_event");
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  int probe_time = 10;
  if (argc == 2) {
    probe_time = atoi(argv[1]);
  }
  std::cout << "Probing for " << probe_time << " seconds" << std::endl;
  sleep(probe_time);

  auto table = bpf.get_hash_table<int, uint64_t>("cpu_time");
  auto num_cores = sysconf(_SC_NPROCESSORS_ONLN);
  for (int i = 0; i < num_cores; i++) {
    std::cout << "CPU " << std::setw(2) << i << " worked for ";
    std::cout << (table[i] / 1000000.0) << " ms." << std::endl;
  }

  auto detach_res = bpf.detach_kprobe("finish_task_switch");
  if (detach_res.code() != 0) {
    std::cerr << detach_res.msg() << std::endl;
    return 1;
  }

  return 0;
}
