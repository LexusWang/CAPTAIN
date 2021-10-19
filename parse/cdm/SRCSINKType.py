SRCSINKType = [
        #  base sensors
        'SRCSINK_ACCELEROMETER',
        'SRCSINK_TEMPERATURE',
        'SRCSINK_GYROSCOPE',
        'SRCSINK_MAGNETIC_FIELD',
        'SRCSINK_HEART_RATE',
        'SRCSINK_LIGHT',
        'SRCSINK_PROXIMITY',
        'SRCSINK_PRESSURE',
        'SRCSINK_RELATIVE_HUMIDITY',

        #  composite sensors
        'SRCSINK_LINEAR_ACCELERATION',
        'SRCSINK_MOTION',
        'SRCSINK_STEP_DETECTOR',
        'SRCSINK_STEP_COUNTER',
        'SRCSINK_TILT_DETECTOR',
        'SRCSINK_ROTATION_VECTOR',
        'SRCSINK_GRAVITY',
        'SRCSINK_GEOMAGNETIC_ROTATION_VECTOR',

        #  temporary 
        'SRCSINK_GPS',
        'SRCSINK_AUDIO',

        #  Environment variables and properties
        'SRCSINK_SYSTEM_PROPERTY',
        'SRCSINK_ENV_VARIABLE',

        #  Android Services
        'SRCSINK_ACCESSIBILITY_SERVICE',
        'SRCSINK_ACTIVITY_MANAGEMENT',
        'SRCSINK_ALARM_SERVICE',
        'SRCSINK_ANDROID_TV',
        'SRCSINK_AUDIO_IO',
        'SRCSINK_BACKUP_MANAGER',
        'SRCSINK_BINDER',
        'SRCSINK_BLUETOOTH',
        'SRCSINK_BOOT_EVENT',
        'SRCSINK_BROADCAST_RECEIVER_MANAGEMENT',
        'SRCSINK_CAMERA',
        'SRCSINK_CLIPBOARD',
        'SRCSINK_COMPONENT_MANAGEMENT',
        'SRCSINK_CONTENT_PROVIDER',
        'SRCSINK_CONTENT_PROVIDER_MANAGEMENT',
        'SRCSINK_DATABASE',
        'SRCSINK_DEVICE_ADMIN',
        'SRCSINK_DEVICE_SEARCH',
        'SRCSINK_DEVICE_USER',
        'SRCSINK_DISPLAY',
        'SRCSINK_DROPBOX',
        'SRCSINK_EMAIL',
        'SRCSINK_EXPERIMENTAL',
        'SRCSINK_FILE',
        'SRCSINK_FILE_SYSTEM',
        'SRCSINK_FILE_SYSTEM_MANAGEMENT',
        'SRCSINK_FINGERPRINT',
        'SRCSINK_FLASHLIGHT',
        'SRCSINK_GATEKEEPER',
        'SRCSINK_HDMI',
        'SRCSINK_IDLE_DOCK_SCREEN',
        'SRCSINK_IMS',
        'SRCSINK_INFRARED',
        'SRCSINK_INSTALLED_PACKAGES',
        'SRCSINK_JSSE_TRUST_MANAGER',
        'SRCSINK_KEYCHAIN',
        'SRCSINK_KEYGUARD',
        'SRCSINK_LOCATION',
        'SRCSINK_MACHINE_LEARNING',
        'SRCSINK_MEDIA',
        'SRCSINK_MEDIA_CAPTURE',
        'SRCSINK_MEDIA_LOCAL_MANAGEMENT',
        'SRCSINK_MEDIA_LOCAL_PLAYBACK',
        'SRCSINK_MEDIA_NETWORK_CONNECTION',
        'SRCSINK_MEDIA_REMOTE_PLAYBACK',
        'SRCSINK_MIDI',
        'SRCSINK_NATIVE',
        'SRCSINK_NETWORK',
        'SRCSINK_NETWORK_MANAGEMENT',
        'SRCSINK_NFC',
        'SRCSINK_NOTIFICATION',
        'SRCSINK_PAC_PROXY',
        'SRCSINK_PERMISSIONS',
        'SRCSINK_PERSISTANT_DATA',
        'SRCSINK_POSIX',
        'SRCSINK_POWER_MANAGEMENT',
        'SRCSINK_PRINT_SERVICE',
        'SRCSINK_PROCESS_MANAGEMENT',
        'SRCSINK_RECEIVER_MANAGEMENT',
        'SRCSINK_RPC',
        'SRCSINK_SCREEN_AUDIO_CAPTURE',
        'SRCSINK_SERIAL_PORT',
        'SRCSINK_SERVICE_CONNECTION',
        'SRCSINK_SERVICE_MANAGEMENT',
        'SRCSINK_SMS_MMS',
        'SRCSINK_SPEECH_INTERACTION',
        'SRCSINK_STATUS_BAR',
        'SRCSINK_SYNC_FRAMEWORK',
        'SRCSINK_TELEPHONY',
        'SRCSINK_TEST',
        'SRCSINK_TEXT_SERVICES',
        'SRCSINK_THREADING',
        'SRCSINK_TIME_EVENT',  
        'SRCSINK_UI',
        'SRCSINK_UID_EVENT',
        'SRCSINK_UI_AUTOMATION',
        'SRCSINK_UI_MODE',
        'SRCSINK_UI_RPC',
        'SRCSINK_USAGE_STATS',
        'SRCSINK_USB',
        'SRCSINK_USER_ACCOUNTS_MANAGEMENT',
        'SRCSINK_USER_INPUT',
        'SRCSINK_VIBRATOR',
        'SRCSINK_WAKE_LOCK',
        'SRCSINK_WALLPAPER_MANAGER',
        'SRCSINK_WAP',
        'SRCSINK_WEB_BROWSER',
        'SRCSINK_WIDGETS',

        #  IPC should only be used for internal IPC instead of network flows
        #  ClearScope might be using this in the interim for flows
        #  Can be a source or a sink
        'SRCSINK_IPC',

        # Ideally not used', but there are legitimate use cases. For
        # example', a file is opened before TA1 technology is started.
        
        'SRCSINK_UNKNOWN']


srcsink_type = {}
for i, item in enumerate(SRCSINKType):
    srcsink_type[item] = i