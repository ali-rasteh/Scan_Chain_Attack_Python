# Scan_Chain_Attack_Python

Scan Chain Attack implementation in Python

## Overview
This project demonstrates an implementation of a Scan Chain Attack using Python. The attack aims to extract the original key of the AES algorithm by manipulating and observing the scan chain bits.

## Files and Structure
- **README.md**: Overview and instructions for the project.
- **Codes/**:
  - **main.py**: Main script containing the implementation of the scan chain attack.
  - **log.txt**: Log file recording the steps and results of the attack.

## Main Functionality
The main script `main.py` includes:
- Functions to convert bit arrays to bit strings and hex values.
- A function `extract_input_indices_in_scan` to identify the input register indices in the scan chain.
- A function `extract_key` to find the RK0 and the original key of the AES algorithm.
- A main function that orchestrates the attack by extracting input indices and key candidates and performing a brute force search to find the final key.

## Usage
1. Ensure you have the required dependencies installed.
2. Run the main script `main.py` to execute the scan chain attack.
3. Check the `log.txt` file for detailed logs and results of the attack.

## Requirements
- Python 3.x
- `cryptography` library

## Installation
Install the required dependencies using pip:
```sh
pip install cryptography
```

## Execution
Run the main script:
```sh
python Codes/main.py
```

## Notes
- The script uses a subprocess call to execute an external executable file for scan chain manipulation.
- The brute force search is performed on all possible combinations of 16 bytes to find the final key.

This README provides a brief overview of the project, its structure, and usage instructions. For more details, refer to the code and logs in the repository.
