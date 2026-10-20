#if os(macOS)
import NetworkExtension
import Dispatch

NEProvider.startSystemExtensionMode()
dispatchMain()
#endif
