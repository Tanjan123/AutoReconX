                         AutoReconX
                              │
                              ▼
                            CLI
                              │
                              ▼
                        Core Engine
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
          Scope          Command Runner      Config
             │                │
             └────────────────┘
                      │
                      ▼
                Recon Modules
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   Discovery       Network          Web
       │              │              │
 Subfinder/dnsx  Naabu/Nmap      httpx/Katana
       │              │              │
       └──────────────┼──────────────┘
                      ▼
                   Parsers
                      ↓
                Normalization
                      ↓
                 Correlation
                      ↓
                 Prioritization
                      ↓
                   SQLite
                      ↓
                  Reporting
                ┌─────┴─────┐
                ▼           ▼
              JSON         HTML
