```markdown
# Window Nat Manager

Window Nat Manager is a lightweight command-line tool written in Go for managing NAT (Network Address Translation) configurations on Windows systems. It leverages Windows’ built-in tools (such as `netsh` and `ipconfig`) to list, create, and delete NAT entries as well as to display network interface details. **Note:** This application must be run with administrator privileges.

## Features

- **Interactive CLI:** Provides an interactive command prompt with various commands.
- **NAT Management:** List, create, and delete NAT rules using Windows’ `netsh interface portproxy` commands.
- **Network Interface Management:** Retrieves and displays detailed information about available network interfaces.
- **Flexible Port Handling:** Supports both specific port mappings and bulk mapping for common ports when no listen port is provided.
- **Error Handling:** Provides detailed output and confirmation prompts for critical operations.

## Prerequisites

- **Operating System:** Windows (with administrative privileges)
- **Go Environment:** Go must be installed (minimum version 1.16 recommended). Download from [golang.org/dl](https://golang.org/dl/).

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/can-acar/Window-Nat-Manager.git
   cd Window-Nat-Manager
   ```

2. **Build the Application**
   ```bash
   go build -o window-nat-manager
   ```

3. **Run the Application**
   ```bash
   ./window-nat-manager
   ```

   Upon launching, you will see a welcome message and a prompt (`NAT>`) for entering commands.

## Usage

### Available Commands

Within the interactive prompt, you can use the following commands:

- **list**  
  Lists all current NAT entries.
  ```bash
  NAT> list
  ```

- **create**  
  Starts an interactive wizard to create a new NAT entry.  
  You can specify the following during the dialogue:
  - Choose a network interface for the listen (source) IP address.
  - Optionally leave the listen port empty to create rules for common ports.
  - Choose a network interface for the target (connect) IP address.
  - Optionally, if the target port is left empty, it defaults to the listen port.
  - Specify the protocol (TCP/UDP; defaults to TCP).
  ```bash
  NAT> create
  ```

- **delete <index>**  
  Deletes a specified NAT entry by its index number.
  ```bash
  NAT> delete 3
  ```

- **delete all**  
  Deletes all NAT entries after confirmation.
  ```bash
  NAT> delete all
  ```

- **delete addr:IP**  
  Deletes all NAT entries associated with the specified listen IP address.
  ```bash
  NAT> delete addr:192.168.1.100
  ```

- **interfaces / if / ifaces**  
  Lists all available network interfaces with IP addresses and other details.
  ```bash
  NAT> interfaces
  ```

- **showif <index>**  
  Displays detailed information about a specific network interface.
  ```bash
  NAT> showif 2
  ```

- **help**  
  Displays help information about available commands.
  ```bash
  NAT> help
  ```

- **exit**  
  Exits the application.
  ```bash
  NAT> exit
  ```

### Example Workflow

1. **List NAT Entries:**
   ```bash
   NAT> list
   ```

2. **Create a New NAT Entry:**
   ```bash
   NAT> create
   ```
   Follow the interactive prompts to select network interfaces and specify the port mapping details. If you leave the listen port empty, the application will create NAT rules for a list of common ports.

3. **Delete a Specific NAT Entry:**
   ```bash
   NAT> delete 2
   ```

4. **View Network Interface Details:**
   ```bash
   NAT> interfaces
   NAT> showif 1
   ```

## Configuration and Operation Details

- **Underlying Mechanism:**  
  The application uses `netsh interface portproxy` commands to manipulate NAT rules:
  - To list NAT entries:  
    `netsh interface portproxy show v4tov4`
  - To add a NAT entry:  
    `netsh interface portproxy add v4tov4 listenport=<port> listenaddress=<IP> connectport=<port> connectaddress=<IP> protocol=<tcp/udp>`
  - To delete a NAT entry:  
    `netsh interface portproxy delete v4tov4 listenport=<port> listenaddress=<IP> protocol=<tcp/udp>`

- **Network Interfaces:**  
  The tool uses `ipconfig /all` to retrieve system network information and parses the output to extract details such as IPv4 address, subnet mask, MAC address, and more.

- **Interactive Prompts:**  
  For operations such as creating or deleting NAT entries, the application prompts the user for confirmation and input. This ensures that potentially disruptive operations (like deleting all entries) are carefully confirmed by the user.

## Contributing

Contributions are welcome! To get started:

1. Fork this repository.
2. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes with clear and descriptive messages.
4. Push your branch and open a pull request describing your changes.

For any major modifications, please open an issue to discuss your proposed changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Support

For issues, questions, or suggestions, please open an issue in this repository or contact the maintainers directly.

Happy NAT managing!
```
```
