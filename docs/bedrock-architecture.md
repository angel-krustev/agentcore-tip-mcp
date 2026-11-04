```mermaid
graph TD
    %% Entities
    User((Human User\nAlice/Bob))
    IdP[Microsoft Entra ID\nIdP]
    App[Streamlit App\nLocal/VPN]
    
    %% AWS Cloud Boundary
    subgraph AWS Cloud Architecture
        ALB[Internal Application Load Balancer]
        
        subgraph VPC - Private Subnets
            subgraph ECS Fargate Task - Zero-Trust Broker
                PlaneA[Plane A: Ingestion\nPort 8080]
                PlaneB[Plane B: Agent Execution\nPort 8081]
                SessionState[(In-Memory\nSession State)]
            end
        end
        
        subgraph Bedrock Managed Service
            Agent[Amazon Bedrock AgentCore\nRuntime & Harness]
        end
        
        subgraph Data & Governance Layer
            STS[AWS STS\nAssumeRole + ProvidedContexts]
            LF[AWS Lake Formation\nNative Row/Column RLS]
            Athena[Amazon Athena]
            S3[(S3 Data Lake\ninsurance_analytics)]
        end
    end

    %% Flow 1: Authentication
    User -- "1. MFA Login (PKCE)" --> IdP
    IdP -- "2. Returns ID Token (JWT)" --> App
    
    %% Flow 2: Session Handoff
    App -- "3. POST /sessions/init\nwith JWT" --> ALB
    ALB -- "Routes 8080" --> PlaneA
    PlaneA -- "Validates JWT" --> SessionState
    PlaneA -- "4. Returns session_ref\n(3600s TTL)" --> App
    
    %% Flow 3: AI Invocation
    App -- "5. InvokeAgent API\nPrompt + session_ref" --> Agent
    
    %% Flow 4: Tool Execution
    Agent -- "6. MCP Tool Call (SigV4)\nquery_lake_formation\nwith session_ref & SQL" --> PlaneB
    PlaneB -- "7. Look up Identity Context" --> SessionState
    
    %% Flow 5: Data Retrieval
    PlaneB -- "8. Exchange for\nIdentity-Enhanced Token" --> STS
    PlaneB -- "9. Execute Query\nas Alice/Bob" --> Athena
    Athena -- "10. Evaluates Propagated Identity" --> LF
    LF -- "11. Enforces Security Policy" --> S3
    
    %% Styling
    classDef frontend fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef aws fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    classDef pep fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px;
    classDef security fill:#fce4ec,stroke:#880e4f,stroke-width:2px;
    
    class App,User frontend;
    class Agent,ALB,Athena,S3 aws;
    class PlaneA,PlaneB,SessionState pep;
    class STS,LF security;