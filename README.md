Fldbg, a Pykd script to debug FlashPlayer

Please in Firefox change the following configuration in about:config
dom.ipc.plugins.hangUITimeoutSecs = 0
dom.ipc.plugins.contentTimeoutSecs = 0
dom.ipc.plugins.processLaunchTimeoutSecs = 0
dom.ipc.plugins.timeoutSecs = 0
dom.ipc.plugins.unloadTimeoutSecs = 0 

In this way we won't trigger the plugin-hang-ui

The script works on Firefox only for now and was tested on Flash >= 17.0.0.188 32bit
Requirements: pykd >= 0.3
