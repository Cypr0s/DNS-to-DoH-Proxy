/**
 * @file    string.c
 * @author  Kristian Luptak
 * @brief   Contains declarations of utility functions for working with strings
 *          
 * @date    2026-10-23
 */

#ifndef UTIL_STRING_H
#define UTIL_STRING_H

#include "common.h"
#include "error.h"
#include <stdint.h>
#include <string.h>
#include "file.h"


/**
 * @brief               Converts string to number within given range
 * 
 * @param input         Input string
 * @param min_boundary  Minimal allowed value
 * @param max_boundary  Maximal allowed value
 * @return              ssize_t, -1 on error
 */
ssize_t convertStrToNum(const char* input, ssize_t min_boundary, ssize_t max_boundary);


/**
 * @brief        Converts 2 bytes to unsigned short
 * 
 * @param input  Input bytes in network order
 * @return       uint16_t 
 */
uint16_t bytesToUShort(const char* input);


/**
 * @brief        Converts 4 bytes to unsigned int
 * 
 * @param input  Input bytes in network order
 * @return       uint32_t 
 */
uint32_t bytesToUint(const char* input);


/**
 * @brief       Checks if domain name is valid
 * 
 * @param name  Input domain name
 * @return      uint8_t, 1 if valid, 0 otherwise
 */
uint8_t isValidDomainName(const char* name);

/**
 * @brief        Converts unsigned short to 2 bytes
 * 
 * @param value  Input value
 * @param output Output buffer
 */
void uShortToBytes(uint16_t value, char *output);

/**
 * @brief        Converts unsigned int to 4 bytes
 * 
 * @param value  Input value
 * @param output Output buffer
 */

void uIntToBytes(uint32_t value, char *output);

#endif // UTIL_STRING_H