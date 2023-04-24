# Project Summary
Create a honeypot application and dashboard to capture and log attack attempts on a website, as well as legitimate requests to access the dashboard, by monitoring all incoming TCP and UDP connections.

## Selected Technologies:
1. Honeypot application: C#/.NET
2. Dashboard: Blazor WebAssembly with ASP.NET Core
3. Database: InfluxDB hosted on a Linux-based EC2 instance
4. Hosting: AWS with Windows-based EC2 instance for the honeypot and dashboard applications

## General Solution:
1. Develop a C#/.NET honeypot application that listens for incoming TCP and UDP connections on all desired ports, including ports 80 (HTTP) and 443 (HTTPS).
2. Log the details of all connection attempts, including the source IP, timestamp, protocol, and port number, and any payloads when applicable.
3. Examine incoming HTTP/HTTPS requests within the honeypot application to determine if they are legitimate requests for the dashboard.
4. Forward legitimate requests to the ASP.NET Core application hosting the Blazor WebAssembly dashboard using HTTP.
5. Relay the response from the ASP.NET Core application back to the original requester.
6. Store logged connection and attack details in InfluxDB for later analysis and visualization in the dashboard.

## Main Challenges:
1. Handling SSL/TLS termination for incoming HTTPS requests in the honeypot application.
2. Forwarding legitimate requests from the honeypot application to the ASP.NET Core application while maintaining proper error handling and request/response handling.
3. Ensuring the honeypot application is secure and stable when exposed directly to the internet.

## Key Considerations:
1. Security: Implement robust security measures to protect the honeypot application and prevent attackers from compromising the system.
2. Performance: Optimize the honeypot application for handling a high volume of incoming connections and processing large amounts of data.
3. Scalability: Design the solution to be easily scalable to accommodate growing traffic and evolving threats.
4. Maintainability: Develop the application with a modular and well-structured codebase to facilitate future updates and enhancements.

By following this plan, we can create a comprehensive honeypot and monitoring solution that captures all incoming TCP and UDP traffic, logs attack attempts, and provides a modern dashboard for analyzing and visualizing the data. This summary can serve as a guide for the development of the project, ensuring that key aspects of the solution are addressed and prioritized.

## few additional key points : 
1. We want the honeypot to capture all incoming traffic, including legitimate requests to the dashboard.
2. The honeypot application will be responsible for handling SSL/TLS termination for incoming HTTPS requests and forwarding legitimate requests to the ASP.NET Core application. The honeypot application will use a single SSL certificate for handling all incoming HTTPS requests. 
3. The preliminary plan is to use HTTP for communication between the honeypot application and the ASP.NET Core application, as the latter will not be directly exposed to the internet.

## Performance Requirements
The honeypot application is not expected to handle a large number of concurrent connections. Response times are not critical, and the expected rate of incoming connections is low (a few connections per minute). As a result, the primary focus should be on the application's security and maintainability, rather than optimizing for high performance and scalability.

# Implementation

1. Architectural Overview: The honeypot application is designed with a modular architecture, separating the responsibilities of each component (listening for connections, handling connections, analyzing requests, logging data, etc.) into different classes. This modular design will facilitate easier updates and maintenance in the future.
2. Security: Ensure that the honeypot application itself is secure and robust. Be cautious with the handling of incoming data, and consider applying input validation and sanitization where appropriate. Implement proper error handling and logging to detect and mitigate potential issues.
3. Maintainability: Develop the application with a well-structured and organized codebase. Use clear naming conventions, comments, and documentation to make it easy for other developers to understand and maintain the code.

The application will be running on a single EC2 instance.
The application name and namespace is SlurpyHoneypot.
In the basic implementation plan of the HoneyPot app(the program name and namespace is "SlurpyHoneypot"), you have defined the following classes and their functions. These might all be modified if you find out there is a better solution, considering the criteria.

`HoneypotApp`:
   - `public async Task Initialize()`: Initializes the application by loading the configuration and setting up the required components.
   - `public async Task Run()`: Starts the application by launching the `PortListener` instances and managing the lifecycle of the application.
   - `public async Task Shutdown()`: Shuts down the application by stopping the `PortListener` instances and performing any necessary cleanup tasks.

`DataLimiter`:
   - `public DataLimiter(int maxDataSize)`: Constructor that initializes the `DataLimiter` with the specified maximum data size (1 MB in this case).
   - `public bool IsLimitExceeded(int receivedDataSize)`: Checks if the received data size exceeds the maximum data size limit. Returns `true` if the limit is exceeded and `false` otherwise.

`RequestAnalyzer`:
   - `public RequestAnalyzer()`: Constructor that initializes the `RequestAnalyzer` with any required settings or patterns for analyzing requests.
   - `public async Task<RequestAnalysisResult> AnalyzeRequest(HttpRequest request)`: Analyzes an incoming `HttpRequest` and returns a `RequestAnalysisResult` object containing information about whether the request is legitimate, an attack attempt, or a crawler/bot.

`InfluxDbLogger`:
   - `public InfluxDbLogger(string connectionString)`: Constructor that initializes the `InfluxDbLogger` with the specified InfluxDB connection string.
   - `public async Task LogConnection(ConnectionDetails connectionDetails)`: Logs the details of an incoming connection (e.g., source IP, timestamp, protocol, port number) in InfluxDB.
   - `public async Task LogAttack(AttackDetails attackDetails)`: Logs the details of an attack attempt (e.g., source IP, timestamp, attack type, payload) in InfluxDB.

`SSLTerminator`:
   - `public SSLTerminator()`: Constructor that initializes the `SSLTerminator` with any required settings, such as SSL certificates.
   - `public async Task<HttpRequest> TerminateSSL(Stream networkStream)`: Accepts a `Stream` (e.g., from a `TcpClient`) and handles the SSL/TLS termination to extract the underlying `HttpRequest`.

   Here is a summary of the classes along with their short descriptions and function signatures:

`Configuration`:
    - Handles loading and retrieving settings from a configuration file or environment variables.
    - `public T GetSetting<T>(string settingName)`: Retrieves the value of the specified setting and returns it as the requested type.

`ConnectionDetails`:
    - Represents the details of a logged connection, including the remote endpoint, protocol, data size, partial data, data hash, and timestamp.
    - No methods, only properties.

`ConnectionHandler`:
    - Processes incoming TCP and UDP connections, logs connection data, and handles SSL/TLS termination and request forwarding for legitimate connections.
    - `public async Task HandleTcpConnection(TcpClient client)`: Processes an incoming TCP connection, logs the data, and calls mock methods for SSL/TLS termination and request forwarding.
    - `public async Task HandleUdpConnection(UdpClient client, IPEndPoint remoteEndPoint, byte[] receivedData)`: Processes an incoming UDP datagram, logs the data, and calls a mock method for request analysis.
    - `private async Task LogConnectionData(TcpClient client, byte[] data)`: Logs the connection details, including the remote endpoint, protocol, data size, partial data, data hash, and timestamp.

`PortListener`:
    - Listens for incoming TCP and UDP connections on specified ports and forwards them to the `ConnectionHandler` for processing.
    - `public PortListener(ProtocolType protocol)`: Constructor that initializes the `PortListener` with the specified protocol (TCP or UDP).
    - `public async Task StartListening()`: Starts listening for incoming TCP or UDP connections on all possible ports.
    - `public async Task StopListening()`: Stops listening for incoming connections and cleans up any ongoing connection handling tasks.

`Program` :
    - The main class that initializes, runs, and shuts down the honeypot application.
    - `public async Task Initialize()`: Initializes the application by loading the configuration and setting up the required components.
    - `public async Task Run()`: Starts the application by launching the `PortListener` instances and managing the lifecycle of the application.
    - `public async Task Shutdown()`: Shuts down the application by stopping the `PortListener` instances and performing any necessary cleanup tasks.