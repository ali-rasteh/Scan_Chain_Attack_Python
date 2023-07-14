import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Specifying some global variables, command_path is for the subprocess exe command call address, input_size in the size of input data, and key, scan_size is the size of scan chain
command_path = ".\\aes_scan_exam_ar7655_windows_amd64.exe"
input_size = 128
scan_size = 256
# input_indices_in_ scan = [32, 28, 67, 88, 243, 149, 240, 73, 45, 150, 68, 39, 77, 207, 179, 199, 185, 20, 203, 46, 111, 169, 167, 13, 191, 130, 4, 106, 194, 83, 255, 239, 223, 182, 7, 202, 61, 14, 245, 34, 161, 195, 41, 36, 153, 40, 122, 76, 100, 215, 112, 95, 129, 171, 66, 126, 114, 219, 144, 10, 121, 55, 154, 35, 125, 222, 54, 177, 208, 209, 93, 12, 2, 212, 226, 214, 11, 65, 21, 50, 1, 156, 135, 33, 236, 38, 29, 204, 183, 228, 181, 69, 97, 178, 85, 198, 105, 96, 63, 159, 15, 220, 25, 254, 80, 87, 217, 3, 131, 246, 231, 148, 225, 200, 99, 252, 49, 189, 152, 224, 9, 124, 48, 192, 146, 82, 233, 74]

# This function converts an array of bits to a bit string
def bit_array_to_bit_string(array):
    bit_string = ""
    for i in range(len(array)):
        bit_string += str(array[i])
    return bit_string

# This funciton converts a bit string to an array of bits
def bit_string_to_bit_array(string):
    bit_array=[]
    for i in range(len(string)):
        bit_array.append(int(string[i]))
    return bit_array

# This function converts an array of bits to an array of hex values
def bit_array_to_hex_array(array):
    size=int(len(array)/4)
    hex_array = [0 for i in range(size)]
    for i in range(size):
        for j in range(4):
            hex_array[i] += array[4 * i + j] << (3 - j)
        hex_array[i] = (hex(hex_array[i]))[2]
    return hex_array

# This function converts an array of hex values to a hex string
def hex_array_to_hex_string(array):
    hex_string = ""
    for i in range(32):
        hex_string += str(array[i])
    return hex_string

# This function extracts input register indices and input register bit map in the scan chain
def extract_input_indices_in_scan() :
    print("Starting to extract the input indices mapping in the scan chain bits...")
    print("Starting to extract the input indices mapping in the scan chain bits...",file=log_file)

    # specifying parameters for subprocess call of the exe file provided for the midterm to run the exe file and get the output for further processing
    command_input = "-input=00000000000000000000000000000000"
    command_clocks = "-clocks=2"
    command_emit = "-emit_scan"
    command_scan = "-scan_only"

    # f = open("output.txt", "w")
    # the array of input indices
    input_indices = []
    input_indices_dic = {}
    input_indices_dic_sorted_by_scan = {}

    # for loop on all the input bits to change them and observe the change in the first clock cycle
    for k in range(input_size):
        input = [0 for i in range(input_size)]
        input[input_size - 1 - k] = 1

        # input_bit_str = bit_array_to_bit_string(input)
        # print(input_bit_str)

        input_hex = bit_array_to_hex_array(input)
        # print(input_hex)

        input_hex_str = hex_array_to_hex_string(input_hex)
        # print(input_hex_str)

        # the subprocess call executes the exe file and gets the output for more processing
        command_input = "-input=" + input_hex_str
        # print(command_input)
        res = subprocess.check_output([command_path, command_input, command_clocks, command_emit, command_scan])
        res = (str(res))[13:-3]
        # We just need the first clock cycle output of the scan chain for input indices mapping
        clk1_chain = res[:256]
        clk2_chain = res[269:]
        # print(res)
        # print(clk1_chain)
        # print(clk2_chain)

        # f.write(clk1_chain)
        # f.write('\n')
        # f.write(clk2_chain)
        # f.write('\n')

        # Finding which bit in the output is changed after changing one bit in the input
        for i in range(scan_size):
            if(clk1_chain[i]=='1'):
                input_indices.append(i)
                input_indices_dic[k]=i

    # Generating the sorted indices based on the input register and the scan chain bits
    input_indices_sorted = input_indices.copy()
    input_indices_sorted.sort()
    # print(input_indices)
    # print(input_indices_sorted)
    for i in range(len(input_indices_sorted)):
        for j in range(len(input_indices_dic)):
            if(input_indices_dic[j]==input_indices_sorted[i]):
                input_indices_dic_sorted_by_scan[input_indices_sorted[i]]=j

    print("Found the input indices in the scan chain ordered by input bits from LSB to MSB:\n",input_indices)
    print("Found the input indices in the scan chain ordered by input bits from LSB to MSB:\n",input_indices,file=log_file)
    print("Found the input indices dictionary in the scan chain ordered by input bits from LSB to MSB:\n", input_indices_dic)
    print("Found the input indices dictionary in the scan chain ordered by input bits from LSB to MSB:\n", input_indices_dic,file=log_file)
    print("Found the input indices dictionary in the scan chain ordered by scan bits from LSB to MSB:\n",input_indices_dic_sorted_by_scan)
    print("Found the input indices dictionary in the scan chain ordered by scan bits from LSB to MSB:\n",input_indices_dic_sorted_by_scan, file=log_file)

    # f.close()
    return input_indices

# This function finds the RK0 and so the original key of the AES algorithm by doing the calculations explained in the related papers
def extract_key():
    print("Starting to extract the byte candidates for RK0 and the main key of the AES algorithm...")
    print("Starting to extract the byte candidates for RK0 and the main key of the AES algorithm...",file=log_file)

    # Correspoding constants for the subprocess call of the exe file for running the algorithm
    command_input = "-input=00000000000000000000000000000001"
    command_clocks = "-clocks=2"
    command_emit = "-emit_scan"
    command_scan = "-scan_only"

    # Getting the initial_pattern at the second clock cycle by giving all zero pattern to the input
    input = [0 for i in range(input_size)]
    input_hex = bit_array_to_hex_array(input)
    input_hex_str = hex_array_to_hex_string(input_hex)
    command_input = "-input=" + input_hex_str
    res = subprocess.check_output([command_path, command_input, command_clocks, command_emit, command_scan])
    res = (str(res))[13:-3]
    clk1_chain = res[:256]
    clk2_chain = res[269:]
    initial_pattern = bit_string_to_bit_array(clk2_chain)
    # RK0_byte_candidate is the array of candidate keys for each byte of the key which could have 2 different values
    RK0_byte_candidate=[[] for i in range(16)]
    # RK0 = [0 for i in range(input_size)]

    # We have a loop on all bytes of the input and key to do the mathematical calculations as described in the papers
    print("Starting the loop on all bytes of input and key registers to find the key candidate bytes...")
    print("Starting the loop on all bytes of input and key registers to find the key candidate bytes...",file=log_file)
    for b in range(16):
        # This is the array of data register indices in the scan chain for the corresponding byte which has 32 elements
        Data_reg_indices_in_scan = []

        print("Starting to find data register indices in scan chain for byte number", b)
        print("Starting to find data register indices in scan chain for byte number", b,file=log_file)
        # In this loop we check all the different combinations of the input data to produce a new pattern and find all the 32 bits of the corresponding data register indices in the scan output
        for pn in range(256):
            # Generate the input
            input = [0 for i in range(input_size)]
            for j in range(8):
                index = b * 8 + j
                input[input_size - 1 - index] = (pn >> j) & 0x01
                # print(i,j,input[input_size-1-index])
            input_hex = bit_array_to_hex_array(input)
            input_hex_str = hex_array_to_hex_string(input_hex)
            command_input = "-input=" + input_hex_str
            res = subprocess.check_output([command_path, command_input, command_clocks, command_emit, command_scan])
            res = (str(res))[13:-3]
            clk1_chain = res[:256]
            clk2_chain = res[269:]
            new_pattern = bit_string_to_bit_array(clk2_chain)

            # Xor the initial and new patterns
            pattern_xor = [bit1 ^ bit2 for bit1, bit2 in zip(initial_pattern, new_pattern)]
            # print(initial_pattern)
            # print(new_pattern)
            # print(pattern_xor)

            # Find the changed bits in the scan chain that are not in the input indices bits and add to the data register indices
            for i in range(scan_size):
                if (pattern_xor[i] == 1 and not (i in input_indices_in_scan) and not (i in Data_reg_indices_in_scan)):
                    Data_reg_indices_in_scan.append(i)
                    # print(i,i in input_indices_in_scan)
        print("Data register indices in scan chain for byte number",b,":\n",Data_reg_indices_in_scan)
        print("Data register indices in scan chain for byte number",b,":\n",Data_reg_indices_in_scan,file=log_file)
        # print(len(Data_reg_indices_in_scan))

        print("Starting to find candidate key bytes for byte number",b)
        print("Starting to find candidate key bytes for byte number",b,file=log_file)
        # This loop produces 2xm and 2xm+1 inputs and checks the scan chain corresponding data register indices to finally find the after RK0 XOR register leading to finding RK0
        for pn in range(128):
            # Generating inputs with 2xm and 2xm+1 patterns
            input_1 = [0 for i in range(input_size)]
            input_2 = [0 for i in range(input_size)]
            for j in range(8):
                index = b * 8 + j
                input_1[input_size - 1 - index] = ((2 * pn) >> j) & 0x01
                input_2[input_size - 1 - index] = ((2 * pn + 1) >> j) & 0x01
            # print(input_1)
            # print(input_2)
            input_1_hex = bit_array_to_hex_array(input_1)
            input_1_hex_str = hex_array_to_hex_string(input_1_hex)
            input_2_hex = bit_array_to_hex_array(input_2)
            input_2_hex_str = hex_array_to_hex_string(input_2_hex)

            command_input = "-input=" + input_1_hex_str
            res = subprocess.check_output([command_path, command_input, command_clocks, command_emit, command_scan])
            res = (str(res))[13:-3]
            clk1_chain = res[:256]
            clk2_chain = res[269:]
            pattern_1 = bit_string_to_bit_array(clk2_chain)

            command_input = "-input=" + input_2_hex_str
            res = subprocess.check_output([command_path, command_input, command_clocks, command_emit, command_scan])
            res = (str(res))[13:-3]
            clk1_chain = res[:256]
            clk2_chain = res[269:]
            pattern_2 = bit_string_to_bit_array(clk2_chain)

            # Count number of ones in the xor of two patterns
            one_cnt = 0
            for i in range(32):
                pattern_xor_bit = pattern_1[Data_reg_indices_in_scan[i]] ^ pattern_2[Data_reg_indices_in_scan[i]]
                # print(pattern_xor)
                one_cnt += pattern_xor_bit
            # Check number of one values to guess the after RK0 XOR register
            if (one_cnt in (9,12,23,24)):
                if(one_cnt == 9):
                    value = 226
                elif(one_cnt == 12):
                    value = 242
                elif (one_cnt == 23):
                    value = 122
                elif (one_cnt == 24):
                    value = 130
                RK0_xor_1 = [0 for i in range(8)]
                RK0_xor_2 = [0 for i in range(8)]
                RK0_byte_1 = [0 for i in range(8)]
                RK0_byte_2 = [0 for i in range(8)]
                # Find the after RK0 XOR candidates
                for j in range(8):
                    RK0_xor_1[8 - 1 - j] = ((value) >> j) & 0x01
                    RK0_xor_2[8 - 1 - j] = ((value+1) >> j) & 0x01
                # Find the RK0 candidate bytes
                for j in range(8):
                    index = b * 8 + j
                    RK0_byte_1[8 - 1 - j] = RK0_xor_1[8 - 1 - j] ^ input_1[input_size - 1 - index]
                    RK0_byte_2[8 - 1 - j] = RK0_xor_2[8 - 1 - j] ^ input_1[input_size - 1 - index]
                    # RK0[input_size - 1 - index] = RK0_xor[8 - 1 - j] ^ input_1[input_size - 1 - index]
                # print(RK0_byte_1)
                # print(RK0_byte_2)
                # Appending the RK0 candidate bytes to the RK0_byte_candidate list
                RK0_byte_candidate[16-1-b].append(RK0_byte_1)
                RK0_byte_candidate[16-1-b].append(RK0_byte_2)
                break
        print("Found candidate key bytes for byte number", b)
        print("Found candidate key bytes for byte number", b,file=log_file)

    print("Found the byte candidates for RK0 and the main key of the AES algorithm, RK0 byte candidates:\n",RK0_byte_candidate)
    print("Found the byte candidates for RK0 and the main key of the AES algorithm, RK0 byte candidates:\n",RK0_byte_candidate,file=log_file)
    return RK0_byte_candidate

# This is the main function which runs the algorithm
if __name__ == '__main__':
    # The path of log file for printing the log
    log_file = open('log.txt', 'a')
    print("Starting the scan chain attack...")
    print("Starting the scan chain attack...",file=log_file)

    # command_input = "-input=00000000000000000000000000000001"
    # command_clocks = "-clocks=2"
    # command_emit = "-emit_scan"
    # command_scan = "-scan_only"
    # res = subprocess.call([path,input,clocks,emit,scan])
    # res = subprocess.check_output([command_path,command_input,command_clocks,command_emit,command_scan])

    # We extract the input register indices in the scan chain using the extract_input_indices_in_scan function
    input_indices_in_scan = extract_input_indices_in_scan()

    # find the RK0 candidates for each byte of the key using the extract_key function
    RK0_byte_candidates = extract_key()
    # RK0_byte_candidates=[[[1, 1, 1, 0, 1, 1, 1, 0], [1, 1, 1, 0, 1, 1, 1, 1]], [[0, 1, 0, 1, 1, 1, 0, 0], [0, 1, 0, 1, 1, 1, 0, 1]],
    #  [[0, 0, 0, 0, 1, 0, 0, 0], [0, 0, 0, 0, 1, 0, 0, 1]], [[1, 0, 0, 0, 0, 0, 1, 0], [1, 0, 0, 0, 0, 0, 1, 1]],
    #  [[0, 0, 0, 1, 1, 1, 0, 0], [0, 0, 0, 1, 1, 1, 0, 1]], [[1, 0, 1, 1, 0, 0, 0, 0], [1, 0, 1, 1, 0, 0, 0, 1]],
    #  [[1, 0, 0, 1, 1, 1, 0, 0], [1, 0, 0, 1, 1, 1, 0, 1]], [[0, 1, 1, 0, 1, 0, 1, 0], [0, 1, 1, 0, 1, 0, 1, 1]],
    #  [[0, 1, 1, 0, 1, 0, 0, 0], [0, 1, 1, 0, 1, 0, 0, 1]], [[0, 1, 1, 1, 0, 0, 0, 0], [0, 1, 1, 1, 0, 0, 0, 1]],
    #  [[0, 0, 1, 0, 0, 1, 0, 0], [0, 0, 1, 0, 0, 1, 0, 1]], [[1, 1, 0, 1, 1, 1, 0, 0], [1, 1, 0, 1, 1, 1, 0, 1]],
    #  [[0, 0, 0, 1, 0, 1, 0, 0], [0, 0, 0, 1, 0, 1, 0, 1]], [[0, 1, 0, 0, 0, 1, 0, 0], [0, 1, 0, 0, 0, 1, 0, 1]],
    #  [[0, 0, 1, 1, 1, 0, 1, 0], [0, 0, 1, 1, 1, 0, 1, 1]], [[0, 0, 1, 1, 1, 1, 1, 0], [0, 0, 1, 1, 1, 1, 1, 1]]]

    print("Starting the brute force search on the all combinations of different key bytes...")
    print("Starting the brute force search on the all combinations of different key bytes...",file=log_file)
    # This for loop is on all the possible combinations of 16 bytes which have 2 candidates each so we have 2^16 different combinations, So this is a brute force search
    for k in range(2**16):
        # We set the value of the key_candidate using RK0_byte_candidates
        key_candidate = [0 for i in range(input_size)]
        for i in range(16):
            for j in range(8):
                index = i * 8 + j
                key_candidate[input_size - 1 - index] = RK0_byte_candidates[16-1-i][(k>>i)&0x01][8-1-j]

        # print(key_candidate)
        key_candidate_hex_str = hex_array_to_hex_string(bit_array_to_hex_array(key_candidate))
        # print(key_candidate)
        # We give the plaintext all zero to the algorithm
        plaintext = "00000000000000000000000000000000"
        key_candidate_bytes = bytes.fromhex(key_candidate_hex_str)
        # print(key_candidate)
        cipher = Cipher(algorithms.AES(key_candidate_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        # Encrypt the plaintext using the candidae key
        ct = encryptor.update(bytes.fromhex(plaintext)) + encryptor.finalize()
        # print(ct.hex())
        # print(str(ct.hex()))
        # At this point we compare the value of the ciphertext with the value of exe file output for all zero data and by doing this brute force we find the final_key
        if(str(ct.hex())=="6F909AEB0BF0F0B7980AEC00D40DE7CE".lower()):
            final_key = key_candidate
            print("Found one final key that works!, Final Key:\n",key_candidate_hex_str)
            print("Found one final key that works!, Final Key:\n",key_candidate_hex_str,file=log_file)

    log_file.close()