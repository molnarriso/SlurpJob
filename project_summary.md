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
2. The honeypot application will be responsible for handling SSL/TLS termination for incoming HTTPS requests and forwarding legitimate requests to the ASP.NET Core application.
3. The preliminary plan is to use HTTP for communication between the honeypot application and the ASP.NET Core application, as the latter will not be directly exposed to the internet.