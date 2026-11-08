//
// SPDX-FileCopyrightText: 2026 Roger Ortiz <roger@r0rt1z2.com>
// SPDX-FileCopyrightText: 2026 SoulSpark <spark_soul@mail.ru>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>
#include <lib/spoof.h>
#include <arch/arm.h>

// Bootloader lock spoofing, added on top of the init-only baseline.
//
// Two runtime patches, both gated behind is_spoofing_enabled():
//   1. seccfg_get_lock_state reports LKS_LOCK to TEE/Keymaster.
//   2. LK's own AVB gate is neutralised so the locked report does not make
//      it demand image authentication (which a patched LK cannot pass).
//
// The fastboot menu thread and the orange-state FORCE_RETURN/NOP patches
// remain excluded; they grew the payload to 11952 bytes and v15 stalled in
// PMIC init on the way in.
//
// --- androidboot.verifiedbootstate ----------------------------------------
//
// The dispatch function at 0x4825D00C reads a state index and selects one of
// four string stubs with a tbb table:
//
//   0x4825D00C: push  {r3, lr}
//   0x4825D00E: ldr   r3, [pc, #68]   ; literal at 0x4825D054 -> __add_pc base
//   0x4825D010: add   r3, pc          ; -> 0x0010FE78 + 0x4825D014 = 0x4836CE8C
//   0x4825D012: ldr   r3, [r3, #0]
//   0x4825D014: ldr   r3, [r3, #0]   ; <-- state index; PATCHED HERE
//   0x4825D016: cmp   r3, #3
//   0x4825D018: bhi   0x4825D02A      ; index > 3 appends nothing
//   0x4825D01A: tbb   [pc, r3]
//   0x4825D01E: 14 02 0e 08          ; table
//
// index -> branch target -> string:
//   0 -> 0x4825D046 -> androidboot.verifiedbootstate=green   (0x482CCAC0)
//   1 -> 0x4825D022 -> androidboot.verifiedbootstate=yellow  (0x482CCA74)
//   2 -> 0x4825D03A -> androidboot.verifiedbootstate=orange  (0x482CCA4C)
//   3 -> 0x4825D02E -> androidboot.verifiedbootstate=red     (0x482CCA9C)
//
// A v21 build wrote movs r3, #0 (0x2300) here assuming index 0 was orange. Index 0
// is green, so the patch ran but changed nothing observable: the device is already
// in state 0. Orange is index 2, i.e. 0x2302.
//
// The state global's literal 0x0010FE78 occurs at exactly one place in the image
// (0x4825D054), so this function is its only reader and forcing the index here
// cannot desynchronise any other consumer. The cmp/bhi guard is left intact and
// index 2 passes it.
//
// Deliberately applied as patch 3 in board_late_init below:
//   PATCH_MEM(0x4825D014, 0x2302);
//
// Do NOT edit the four .rodata strings in place. They are selected by pointer, and
// overwriting them previously caused Tier9 boot-loops.

void board_early_init(void) {
    printf("Entering early init for Realme X7 Max 5G (cupida)\n");
}

void board_late_init(void) {
    printf("Entering late init for Realme X7 Max 5G (cupida)\n");

    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 1);

    if (!is_spoofing_enabled())
        return;

    printf("Kaeru: bootloader lock spoofing enabled.\n");

    // --- 1. Report LKS_LOCK to TEE/Keymaster -------------------------
    // seccfg_get_lock_state (0x48286B68), verified Thumb:
    //   movs r1, #4    (0x2104) LKS_LOCK
    //   str  r1, [r0]  (0x6001) *lock_state = 4
    //   movs r0, #0    (0x2000) return 0 / SUCCESS
    //   bx   lr        (0x4770)
    PATCH_MEM(0x48286B68, 0x2104, 0x6001, 0x2000, 0x4770);

    // --- 2. Stop LK from enforcing AVB because of that lock state ----
    // Reporting LKS_LOCK makes LK demand image authentication, which a
    // patched LK cannot satisfy. v18 died here:
    //   [SEC_POLICY] lock_state = 0x4
    //   [avb] img_auth_required = 1
    //   ERROR: vbmeta: Public key used to sign data rejected.
    //   panic ... ASSERT at boot_info.c:617: g_boot_info.hdr_loaded
    //
    // FUN_48274E70 computes img_auth_required from get_vfy_policy and
    // prints it. Its only two callers are 0x48275012 and 0x482752A6.
    // The consumer normalises the result immediately:
    //   0x48275012: bl   0x48274E70
    //   0x48275016: clz  r6, r0
    //   0x4827501C: lsrs r6, r6, #5
    // clz(x)>=26 for every x!=0, so (clz(x)>>5)&1 is 1 only when x==0.
    // r6 is therefore "auth not required". Replacing the call with
    // "movs r0, #0" (0x2000) makes r6 = 1 unconditionally, so LK loads
    // boot/recovery without verifying vbmeta, while patch 1 above still
    // reports lock_state 0x4 to TEE.
    //
    // The bl is two halfwords (0xF7FF 0xFF2D). v19 wrote only the first
    // one, so 0xFF2D survived and desynced the stream into a bogus
    // vpmin.u32 + bge.w; LK hung at the realme logo instead. Both
    // halfwords must be replaced, hence the trailing nop.
    PATCH_MEM(0x48275012, 0x2000, 0xBF00);

    // --- 3. Report unlocked state to the kernel cmdline ------------------
    // 0x4825D014 is `ldr r3, [r3, #0]` inside the androidboot.verifiedbootstate
    // dispatch at 0x4825D00C. It loads the state index that the tbb table at
    // 0x4825D01E then selects:
    //   0 -> green   1 -> yellow   2 -> orange   3 -> red
    // v21 wrote movs r3, #0 here, which is green — the state this device is
    // already in, so it looked like a no-op. Orange is index 2. The `cmp r3,#3`
    // / `bhi` guard at 0x4825D016 is untouched and index 2 passes it.
    //
    // The state global's __add_pc literal 0x0010FE78 appears at exactly one
    // place in the image (0x4825D054), so this function is its only reader and
    // forcing the index cannot desynchronise another subsystem.
    //
    // This is independent of patch 1: the lock_state spoof goes to TEE/Keymaster,
    // this only changes the string the kernel sees. Unlocked devices report
    // orange, so 2 is also the semantically correct value.
    PATCH_MEM(0x4825D014, 0x2302);
}
