Description: Keys the registry triage rules read
Author: opensearch-mcp
Version: 1
Id: 6a2f3c1e-4b7d-4e0a-9c55-0d2b8f6e1a54
Keys:
    -
        Description: AppInit_DLLs
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: AppInit_DLLs
        Recursive: false
    -
        Description: AppInit_DLLs (WOW64)
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: AppInit_DLLs
        Recursive: false
    -
        Description: Winlogon Shell
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Shell
        Recursive: false
    -
        Description: Winlogon Userinit
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Userinit
        Recursive: false
    -
        Description: Winlogon mpnotify
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: mpnotify
        Recursive: false
    -
        Description: Command Processor AutoRun
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Microsoft\Command Processor
        ValueName: AutoRun
        Recursive: false
    -
        Description: Command Processor AutoRun (WOW64)
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Wow6432Node\Microsoft\Command Processor
        ValueName: AutoRun
        Recursive: false
    -
        Description: Terminal Services InitialProgram (policy)
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Policies\Microsoft\Windows NT\Terminal Services
        ValueName: InitialProgram
        Recursive: false
    -
        Description: Active Setup StubPath
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Microsoft\Active Setup\Installed Components\*
        ValueName: StubPath
        Recursive: false
    -
        Description: Active Setup StubPath (WOW64)
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Wow6432Node\Microsoft\Active Setup\Installed Components\*
        ValueName: StubPath
        Recursive: false
    -
        Description: NetSh helper DLLs
        HiveType: SOFTWARE
        Category: Triage
        KeyPath: Microsoft\NetSh
        Recursive: false
    -
        Description: BootExecute
        HiveType: SYSTEM
        Category: Triage
        KeyPath: ControlSet00*\Control\Session Manager
        ValueName: BootExecute
        Recursive: false
    -
        Description: LSA Authentication Packages
        HiveType: SYSTEM
        Category: Triage
        KeyPath: ControlSet00*\Control\Lsa
        ValueName: Authentication Packages
        Recursive: false
    -
        Description: LSA Security Packages
        HiveType: SYSTEM
        Category: Triage
        KeyPath: ControlSet00*\Control\Lsa
        ValueName: Security Packages
        Recursive: false
    -
        Description: LSA Security Packages (OSConfig)
        HiveType: SYSTEM
        Category: Triage
        KeyPath: ControlSet00*\Control\Lsa\OSConfig
        ValueName: Security Packages
        Recursive: false
    -
        Description: LSA Notification Packages
        HiveType: SYSTEM
        Category: Triage
        KeyPath: ControlSet00*\Control\Lsa
        ValueName: Notification Packages
        Recursive: false
    -
        Description: Print Monitors
        HiveType: SYSTEM
        Category: Triage
        KeyPath: ControlSet00*\Control\Print\Monitors\*
        ValueName: Driver
        Recursive: false
    -
        Description: Service ImagePath
        HiveType: SYSTEM
        Category: Triage
        KeyPath: ControlSet00*\Services\*
        ValueName: ImagePath
        Recursive: false
