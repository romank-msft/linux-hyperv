PATCHES

1) arm64: hyperv: Use SMCCC to detect hypervisor presence

The arm64 Hyper-V startup path relies on ACPI to detect
running under a Hyper-V compatible hypervisor. That
doesn't work on non-ACPI systems.

Hoist the ACPI detection logic into a separate function. Then
use the vendor-specific hypervisor service call (implemented
recently in Hyper-V) via SMCCC in the non-ACPI case.

2) Drivers: hv: Enable VTL mode for arm64

Kconfig dependencies for arm64 guests on Hyper-V require that be
ACPI enabled, and limit VTL mode to x86/x64. To enable VTL mode
on arm64 as well, update the dependencies. Since VTL mode requires
DeviceTree instead of ACPI, don’t require arm64 guests on Hyper-V
to have ACPI unconditionally.

3) Drivers: hv: Provide arch-neutral implementation of get_vtl()

To run in the VTL mode, Hyper-V drivers have to know what
VTL the system boots in, and the arm64/hyperv code does not
have the means to compute that.

Refactor the code to hoist the function that detects VTL,
make it arch-neutral to be able to employ it to get the VTL
on arm64. Move the variable that holds the VTL into the
arch-neutal code. No functional changes.

Fix the hypercall output address in `get_vtl(void)`
not to overlap with the hypercall input area to adhere to
the Hyper-V TLFS.

4) arm64: hyperv: Boot in a Virtual Trust Level

To run in the VTL mode, Hyper-V drivers have to know what
VTL the system boots in, and the arm64/hyperv code does not
update the variable that stores the value.

Update the variable to enable the Hyper-V drivers to boot
in the VTL mode and print the VTL the code runs in.

5) dt-bindings: microsoft,vmbus: Add GIC and DMA coherence to the example

The existing example lacks the GIC interrupt controller property
making it not possible to boot on ARM64, and it lacks the DMA
coherence property making the kernel do more work on maintaining
CPU caches on ARM64 although the VMBus trancations are cache-coherent.

Add the GIC node, specify DMA coherence, and define interrupt-parent
and interrupts properties in the example to provide a complete reference
for platforms utilizing GIC-based interrupts, and add the DMA coherence
property to not do extra work on the architectures where DMA defaults to
non cache-coherent.

6) Drivers: hv: vmbus: Get the IRQ number from DeviceTree

The VMBus driver uses ACPI for interrupt assignment on
arm64 hence it won't function in the VTL mode where only
DeviceTree can be used.

Update the VMBus driver to discover interrupt configuration
from DT.

7) PCI: hv: Get vPCI MSI IRQ domain from DeviceTree

The hyperv-pci driver uses ACPI for MSI IRQ domain configuration on
arm64. It won't be able to do that in the VTL mode where only DeviceTree
can be used.

Update the hyperv-pci driver to get vPCI MSI IRQ domain in the DeviceTree
case, too.
