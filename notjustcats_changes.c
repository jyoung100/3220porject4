#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

// FAT12 constants 
#define BYTES_PER_SECTOR 512
#define RESERVED_SECTORS 1  //Boot sector      
#define NUM_FATS 2                  
#define SECTORS_PER_FAT 9           
#define ROOT_DIR_ENTRIES 224        
#define ROOT_DIR_SECTORS 14         

// Boot Sector structure - only need to read sectors_per_cluster
typedef struct {
    uint8_t _padding[13];           // jump[3] + oem_name[8] + bytes_per_sector[2] = 13 bytes
    uint8_t sectors_per_cluster;    // Byte 13: Only field we need to read (may vary)
    uint8_t _rest[498];             // Rest of 512-byte boot sector
} __attribute__((packed)) BootSector;

// FAT12 Directory Entry 
// Only fields actually used by the program are named; others are padding
typedef struct {
    char filename[8];    //8 bytes       
    char extension[3];   //3 bytes       
    uint8_t attributes;  //1 byte
    //bytes 12 - 25      
    uint8_t _padding1[10];      // reserved to last access date
    uint16_t _padding2;     // time
    uint16_t _padding3;    //date
    uint16_t starting_cluster; //2 bytes
    uint32_t file_size;   //4 bytes
} __attribute__((packed)) DirEntry;

// File information 
typedef struct {
    char path[512];
    uint32_t size;
    uint16_t starting_cluster;
    int is_deleted;
    char extension[4];
} FileInfo;

// Global variables
uint8_t *disk_image = NULL;
size_t image_size = 0;
uint8_t sectors_per_cluster = 0;  // Read from boot sector
uint8_t *fat_table = NULL;
FileInfo *files = NULL;
int file_count = 0;
int file_capacity = 0;

// Function prototypes
int read_disk_image(const char *filename);
void read_boot_sector(void);
void read_fat_table(void);
uint16_t get_fat_entry(uint16_t cluster);
void parse_directory(uint32_t dir_offset, uint32_t dir_size, const char *path);
void recover_and_write_file(FileInfo *file, FILE *fp);
void print_files(void);
void write_recovered_files(const char *output_dir);

// Read the entire disk image into memory
int read_disk_image(const char *filename) {
    int fd = open(filename, O_RDONLY);
    
    struct stat st;
    fstat(fd, &st);
    
    image_size = st.st_size;
    disk_image = malloc(image_size);
    
    
    read(fd, disk_image, image_size);
    
    close(fd);
    return 0;
}

// Read sectors_per_cluster from boot sector
void read_boot_sector(void) {
    BootSector *bs = (BootSector *)disk_image;
    sectors_per_cluster = bs->sectors_per_cluster;
}

// Read FAT table
void read_fat_table(void) {
    uint32_t fat_offset = RESERVED_SECTORS * BYTES_PER_SECTOR;
    uint32_t fat_size = SECTORS_PER_FAT * BYTES_PER_SECTOR;
    
    fat_table = malloc(fat_size);
    
    memcpy(fat_table, disk_image + fat_offset, fat_size);
}

// Get FAT entry for a cluster (FAT12 uses 12-bit entries)
uint16_t get_fat_entry(uint16_t cluster) {
    uint32_t fat_index = cluster * 3 / 2;
    
    if (cluster % 2 == 0) {
        // Even cluster: lower 12 bits
        uint16_t lower_byte = fat_table[fat_index];
        uint16_t upper_nibble = fat_table[fat_index + 1] & 0x0F;
        upper_nibble = upper_nibble << 8;
        uint16_t combined = lower_byte | upper_nibble;
        result = combined & 0x0FFF;
        return result;
        //return (fat_table[fat_index] | ((fat_table[fat_index + 1] & 0x0F) << 8)) & 0x0FFF;
    } else {
        // Odd cluster: upper 12 bits
        uint16_t lower_nibble = fat_table[fat_index] >> 4;
        uint16_t upper_byte = fat_table[fat_index + 1] << 4;
        uint16_t combined = lower_nibble | upper_byte;
        result = combined & 0x0FFF;
        return result;
        //return ((fat_table[fat_index] >> 4) | (fat_table[fat_index + 1] << 4)) & 0x0FFF;
    }
}

// Add file to the list
void add_file(char *path, uint32_t size, uint16_t cluster, int is_deleted, char *ext) {
    if (file_count >= file_capacity) {
        if(file_capacity == 0) {
            file_capacity = 16;
        } else {
            file_capacity *= 2;
        }
        //file_capacity = file_capacity == 0 ? 16 : file_capacity * 2;
        files = realloc(files, file_capacity * sizeof(FileInfo));
    }
    
    FileInfo *file = &files[file_count];
    strncpy(file->path, path, sizeof(file->path) - 1);
    file->path[sizeof(file->path) - 1] = '\0';
    file->size = size;
    file->starting_cluster = cluster;
    file->is_deleted = is_deleted;
    strncpy(file->extension, ext, sizeof(file->extension) - 1);
    file->extension[sizeof(file->extension) - 1] = '\0';
    file_count++;
}

// Parse directory entries
void parse_directory(uint32_t dir_offset, uint32_t dir_size, char *path) {
    uint32_t num_entries = dir_size / 32;
    
    for (uint32_t i = 0; i < num_entries; i++) {
        DirEntry *entry = (DirEntry *)(disk_image + dir_offset + i * 32);
        
        // Get first character as unsigned to handle all byte values correctly
        unsigned char first_char = (unsigned char)entry->filename[0];
        
        // Skip empty entries
        if (first_char == 0x00) {
            break;
        }
        
        // Skip volume label entries
        if (entry->attributes == 0x08) {
            continue;
        }
        
        // Skip "." and ".." entries
        if (first_char == 0x2E) {
            continue;
        }
        
        // Check if file is deleted (0xE5 marks deleted files)
        int is_deleted = (first_char == 0xE5);
        
        // Build filename
        char filename[13];
        memset(filename, 0, sizeof(filename));  // Initialize to zero
        if (is_deleted) {
            filename[0] = '_';
            memcpy(filename + 1, entry->filename + 1, 7);
        } else {
            memcpy(filename, entry->filename, 8);
        }
        
        // Remove trailing spaces from filename
        int name_len = 8;
        while (name_len > 0 && filename[name_len - 1] == ' ') {
            name_len--;
        }
        filename[name_len] = '\0';
        
        // Ensure filename is properly null-terminated
        filename[sizeof(filename) - 1] = '\0';
        
        // Build extension
        char ext[4];
        memcpy(ext, entry->extension, 3);
        ext[3] = '\0';
        
        // Remove trailing spaces from extension
        int ext_len = 3;
        while (ext_len > 0 && ext[ext_len - 1] == ' ') {
            ext_len--;
        }
        ext[ext_len] = '\0';
        
        // Build full path
        char full_path[512];
        if (strlen(path) == 1 && path[0] == '/') {
            snprintf(full_path, sizeof(full_path), "/%s", filename);
        } else {
            snprintf(full_path, sizeof(full_path), "%s/%s", path, filename);
        }
        
        // Add extension if present
        if (ext_len > 0) {
            strcat(full_path, ".");
            strncat(full_path, ext, ext_len);
        }
        
        // Check if it's a directory
        if (entry->attributes & 0x10) {
            // It's a directory
            if (entry->starting_cluster >= 2) {
                // Calculate directory data offset
                uint32_t data_start = (RESERVED_SECTORS + 
                                      NUM_FATS * SECTORS_PER_FAT +
                                      (ROOT_DIR_ENTRIES * 32 + BYTES_PER_SECTOR - 1) / BYTES_PER_SECTOR) *
                                      BYTES_PER_SECTOR;
                
                // Parse subdirectory
                // For deleted directories, just parse first cluster
                // For normal directories, follow FAT chain
                if (is_deleted || entry->file_size == 0) {
                    // Deleted directory or zero-size: just parse first cluster
                    uint32_t dir_cluster_offset = data_start + 
                        (entry->starting_cluster - 2) * sectors_per_cluster * BYTES_PER_SECTOR;
                    uint32_t dir_size = sectors_per_cluster * BYTES_PER_SECTOR;
                    parse_directory(dir_cluster_offset, dir_size, full_path);
                } else {
                    // Normal directory: follow FAT chain
                    uint16_t current_cluster = entry->starting_cluster;
                    uint32_t total_size = 0;
                    uint32_t max_size = entry->file_size > 0 ? entry->file_size : 
                                       sectors_per_cluster * BYTES_PER_SECTOR;
                    
                    while (current_cluster >= 2 && current_cluster < 0xFF0 && total_size < max_size) {
                        uint32_t dir_cluster_offset = data_start + 
                            (current_cluster - 2) * sectors_per_cluster * BYTES_PER_SECTOR;
                        uint32_t cluster_size = sectors_per_cluster * BYTES_PER_SECTOR;
                        uint32_t size_to_parse = max_size - total_size;
                        if (size_to_parse > cluster_size) {
                            size_to_parse = cluster_size;
                        }
                        
                        parse_directory(dir_cluster_offset, size_to_parse, full_path);
                        total_size += cluster_size;
                        
                        uint16_t fat_entry = get_fat_entry(current_cluster);
                        if (fat_entry >= 0xFF8) {
                            break;
                        }
                        current_cluster = fat_entry;
                    }
                }
            }
        } else {
            // It's a file
            // Add file if it's not empty (we already skip 0x00 entries above)
            // Include both normal files and deleted files (0xE5)
            // We use first_char which was already checked above, so this should always be true
            // but we check again to be safe
            if (first_char != 0x00) {
                add_file(full_path, entry->file_size, entry->starting_cluster, is_deleted, ext);
            }
        }
    }
}

// Recover file data and write to file
void recover_and_write_file(FileInfo *file, FILE *fp) {
    if (file->starting_cluster < 2) {
        return; // Invalid cluster
    }
    
    // Calculate data area start
    uint32_t data_start = (RESERVED_SECTORS + 
                          NUM_FATS * SECTORS_PER_FAT +
                          (ROOT_DIR_ENTRIES * 32 + BYTES_PER_SECTOR - 1) / BYTES_PER_SECTOR) *
                          BYTES_PER_SECTOR;
    
    uint32_t bytes_per_cluster = sectors_per_cluster * BYTES_PER_SECTOR;
    uint32_t bytes_recovered = 0;
    uint16_t current_cluster = file->starting_cluster;
    
    if (file->is_deleted) {
        // For deleted files, read clusters sequentially until we hit a used cluster or reach file size
        uint32_t clusters_needed = (file->size + bytes_per_cluster - 1) / bytes_per_cluster;
        
        for (uint32_t i = 0; i < clusters_needed && bytes_recovered < file->size; i++) {
            uint16_t fat_entry = get_fat_entry(current_cluster);
            
            // If FAT entry is not 0x000, stop (cluster is in use)
            if (fat_entry != 0x000 && fat_entry < 0xFF8) {
                break;
            }
            
            // Read cluster data
            uint32_t cluster_offset = data_start + (current_cluster - 2) * bytes_per_cluster;
            uint32_t bytes_to_read = file->size - bytes_recovered;
            if (bytes_to_read > bytes_per_cluster) {
                bytes_to_read = bytes_per_cluster;
            }
            
            fwrite(disk_image + cluster_offset, 1, bytes_to_read, fp);
            bytes_recovered += bytes_to_read;
            
            // Move to next cluster
            current_cluster++;
            
            // Check if we've exceeded valid cluster range
            if (current_cluster >= 0xFF0) {
                break;
            }
        }
    } else {
        // For normal files, follow FAT chain
        while (current_cluster >= 2 && current_cluster < 0xFF0 && bytes_recovered < file->size) {
            uint32_t cluster_offset = data_start + (current_cluster - 2) * bytes_per_cluster;
            uint32_t bytes_to_read = file->size - bytes_recovered;
            if (bytes_to_read > bytes_per_cluster) {
                bytes_to_read = bytes_per_cluster;
            }
            
            fwrite(disk_image + cluster_offset, 1, bytes_to_read, fp);
            bytes_recovered += bytes_to_read;
            
            // Get next cluster from FAT
            uint16_t fat_entry = get_fat_entry(current_cluster);
            if (fat_entry >= 0xFF8) {
                break; // End of file
            }
            current_cluster = fat_entry;
        }
    }
}

// Print all files
void print_files(void) {
    for (int i = 0; i < file_count; i++) {
        const char *status = files[i].is_deleted ? "DELETED" : "NORMAL";
        printf("FILE\t%s\t%s\t%u\n", status, files[i].path, files[i].size);
    }
}

// Write recovered files to output directory
void write_recovered_files(const char *output_dir) {
    int file_index = 0;
    
    for (int i = 0; i < file_count; i++) {
        char output_path[512];
        snprintf(output_path, sizeof(output_path), "%s/file%d%s", 
                output_dir, file_index, files[i].extension[0] ? "." : "");
        if (files[i].extension[0]) {
            strcat(output_path, files[i].extension);
        }
        
        FILE *fp = fopen(output_path, "wb");
        if (!fp) {
            perror("fopen");
            continue;
        }
        
        // Recover and write file data
        recover_and_write_file(&files[i], fp);
        
        fclose(fp);
        file_index++;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <image_filename> <output_directory>\n", argv[0]);
        return 1;
    }
    
    const char *image_filename = argv[1];
    const char *output_dir = argv[2];
    
    // Read disk image
    if (read_disk_image(image_filename) < 0) {
        return 1;
    }
    
    // Read sectors_per_cluster from boot sector
    read_boot_sector();
    
    // Read FAT table
    read_fat_table();
    
    // Calculate root directory offset
    uint32_t root_dir_offset = (RESERVED_SECTORS + 
                               NUM_FATS * SECTORS_PER_FAT) *
                               BYTES_PER_SECTOR;
    uint32_t root_dir_size = ROOT_DIR_ENTRIES * 32;
    
    // Parse root directory
    parse_directory(root_dir_offset, root_dir_size, "/");
    
    // Print files
    print_files();
    
    // Write recovered files
    write_recovered_files(output_dir);
    
    // Cleanup
    free(disk_image);
    free(fat_table);
    free(files);
    
    return 0;
}
