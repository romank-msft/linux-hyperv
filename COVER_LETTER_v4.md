This patch set allows the Hyper-V code to boot on ARM64 inside a Virtual Trust
Level. These levels are a part of the Virtual Secure Mode documented in the
Top-Level Functional Specification available at
https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm.

The OpenHCL paravisor https://github.com/microsoft/openvmm/tree/main/openhcl
can serve as a practical application of these patches on ARM64.

For validation, I built kernels for the {x86_64, ARM64} x {VTL0, VTL2} set with
a small initrd embedded into the kernel and booted the Hyper-V VMs off of that.

[V4]
    - Fixed wording to match acronyms defined in the "Terms and Abbreviations"
      section of the SMCCC specification throughout the patch series.
    - Replaced the hypervisor ID containing ASCII with an UUID as
      required by the specification. It is of the random kind, produced with
      `uuidgen -r`.
    - Added an explicit check for `SMCCC_RET_NOT_SUPPORTED` when discovering the
      hypervisor presence to make the backward compatibility obvious.
    - Split the fix for `get_vtl(void)` out to make it easier to backport.
    - Refactored the configuration options as requested to eliminate the risk
      of building non-functional kernels with randomly selected options.
    - Refactored the changes not to introduce an additional file with
      a one-line function.
    - Fixed change description for the VMBus DeviceTree changes, used
      `scripts/get_maintainers.pl` on the latest kernel to get the up-to-date list
      of maintainers as requested.
    - Removed the added (paranoidal+superfluous) checks for DMA coherence in the
      VMBus driver and instead relied on the DMA and the OF subsystem code.
    - Used another set of APIs for discovering the hardware interrupt number
      in the VMBus driver to be able to build the driver as a module.
    - Split the non-functional change to the VMBus driver code out to make
      reviewing the functional change easier. Rename the newly introduced
      `get_vmbus_root_device(void)` function to `hv_get_vmbus_root_device(void)`
      as requested.
    - Applied the suggested small-scale refactoring to simplify changes to the Hyper-V
      PCI driver. Taking the offered liberty of doing the large scale refactoring
      in another patch series.
    - Added a fix for the issue discovered internally where the CPU would not
      get the interrupt from a PCI device attached to VTL2 as the shared peripheral
      interrupt number (SPI) was not offset by 32 (the first valid SPI number).

[V3]
    https://lore.kernel.org/lkml/20240726225910.1912537-1-romank@linux.microsoft.com/
    - Employed the SMCCC function recently implemented in the Microsoft Hyper-V
      hypervisor to detect running on Hyper-V/arm64. No dependence on ACPI/DT is
      needed anymore although the source code still falls back to ACPI as the new
      hypervisor might be available only in the Windows Insiders channel just
      yet.
    - As a part of the above, refactored detecting the hypervisor via ACPI FADT.
    - There was a suggestion to explore whether it is feasible or not to express
      that ACPI must be absent for the VTL mode and present for the regular guests
      in the Hyper-V Kconfig file.
      My current conclusion is that this will require refactoring in many places.
      That becomes especially convoluted on x86_64 due to the MSI and APIC
      dependencies. I'd ask to let us tackle that in another patch series (or chalk
      up to nice-have's rather than fires to put out) to separate concerns and
      decrease chances of breakage.
    - While refactoring `get_vtl(void)` and the related code, fixed the hypercall
      output address not to overlap with the input as the Hyper-V TLFS mandates:
      "The input and output parameter lists cannot overlap or cross page boundaries."
      See https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
      for more.
      Some might argue that should've been a topic for a separate patch series;
      I'd counter that the change is well-contained (one line), has no dependencies,
      and makes the code legal.
    - Made the VTL boot code (c)leaner as was suggested.
    - Set DMA cache coherency for the VMBus.
    - Updated DT bindings in the VMBus documentation (separated out into a new patch).
    - Fixed `vmbus_set_irq` to use the API that works both for the ACPI and OF.
    - Reworked setting up the vPCI MSI IRQ domain in the non-ACPI case. The logic
      looks a bit fiddly/ad-hoc as I couldn't find the API that would fit the bill.
      Added comments to explain myself.

[V2]
    https://lore.kernel.org/all/20240514224508.212318-1-romank@linux.microsoft.com/
    - Decreased number of #ifdef's
    - Updated the wording in the commit messages to adhere to the guidlines
    - Sending to the correct set of maintainers and mail lists

[V1]
    https://lore.kernel.org/all/20240510160602.1311352-1-romank@linux.microsoft.com/
