#include <cassert>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <ctime>

// Function to perform XOR encryption/decryption
std::string encrypt_decrypt(const std::string& source, const std::string& key)
{
    const auto key_length = key.length();
    const auto source_length = source.length();

    assert(key_length > 0);
    assert(source_length > 0);

    std::string output = source;

    // Perform XOR encryption/decryption
    for (size_t i = 0; i < source_length; ++i)
    {
        output[i] = source[i] ^ key[i % key_length];
    }

    assert(output.length() == source_length);
    return output;
}

// Function to read the contents of a file into a string
std::string read_file(const std::string& filename)
{
    std::ifstream file(filename);
    std::ostringstream content;

    if (file)
    {
        content << file.rdbuf();
    }
    else
    {
        std::cerr << "Could not open file " << filename << std::endl;
        return "";
    }

    return content.str();
}

// Function to extract the student's name from the file content
std::string get_student_name(const std::string& string_data)
{
    size_t pos = string_data.find('\n');
    if (pos != std::string::npos)
    {
        return string_data.substr(0, pos);
    }
    return "";
}

// Function to save data to a file in a specified format
void save_data_file(const std::string& filename, const std::string& student_name, const std::string& key, const std::string& data)
{
    std::ofstream file(filename);
    if (file)
    {
        // Get current date
        std::time_t t = std::time(nullptr);
        std::tm* now = std::localtime(&t);
        file << student_name << '\n';
        file << (now->tm_year + 1900) << '-' 
             << (now->tm_mon + 1) << '-' 
             << now->tm_mday << '\n';
        file << key << '\n';
        file << data;
    }
    else
    {
        std::cerr << "Could not open file " << filename << std::endl;
    }
}

int main()
{
    std::cout << "Encryption Decryption Test!" << std::endl;

    const std::string file_name = "inputdatafile.txt";
    const std::string encrypted_file_name = "encrypteddatafile.txt";
    const std::string decrypted_file_name = "decrypteddatafile.txt";
    const std::string source_string = read_file(file_name);
    const std::string key = "password";

    if (source_string.empty())
    {
        std::cerr << "No data read from file: " << file_name << std::endl;
        return 1;
    }

    const std::string student_name = get_student_name(source_string);

    const std::string encrypted_string = encrypt_decrypt(source_string, key);
    save_data_file(encrypted_file_name, student_name, key, encrypted_string);

    const std::string decrypted_string = encrypt_decrypt(encrypted_string, key);
    save_data_file(decrypted_file_name, student_name, key, decrypted_string);

    std::cout << "Read File: " << file_name << " - Encrypted To: " << encrypted_file_name << " - Decrypted To: " << decrypted_file_name << std::endl;

    return 0;
}
