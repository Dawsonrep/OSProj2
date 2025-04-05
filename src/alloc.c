#include "alloc.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define ALIGNMENT 16 /**< The alignment of the memory blocks */
#define MAGIC_NUMBER 0x01234567 

static free_block *HEAD = NULL; /**< Pointer to the first element of the free list */

/**
 * Split a free block into two blocks
 *
 * @param block The block to split
 * @param size The size of the first new split block
 * @return A pointer to the first block or NULL if the block cannot be split
 */
void *split(free_block *block, int size) {
    if (block->size < size + sizeof(free_block)) {
        return NULL;
    }

    free_block *new_block = (free_block *)((char *)block + size);

    new_block->size = block->size - size;
    new_block->next = block->next;

    block->size = size;
    block->next = new_block;

    return block;
}

/**
 * Find the previous neighbor of a block
 *
 * @param block The block to find the previous neighbor of
 * @return A pointer to the previous neighbor or NULL if there is none
 */
free_block *find_prev(free_block *block) {
    if (HEAD == NULL || block == NULL) {
        return NULL;
    }

    free_block *curr = HEAD;
    while (curr != NULL) {
        if (curr->next == block) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/**
 * Find the next neighbor of a block
 *
 * @param block The block to find the next neighbor of
 * @return A pointer to the next neighbor or NULL if there is none
 */
free_block *find_next(free_block *block) {
    if (block == NULL) {
        return NULL;
    }
    return block->next;
}

/**
 * Remove a block from the free list
 *
 * @param block The block to remove
 */
void remove_free_block(free_block *block) {
    if (block == NULL) {
        return;
    }

    if (HEAD == block) {
        HEAD = block->next;
        return;
    }

    free_block *curr = HEAD;
    while (curr != NULL && curr->next != block) {
        curr = curr->next;
    }

    if (curr != NULL) {
        curr->next = block->next;
    }
}

/**
 * Coalesce neighboring free blocks
 *
 * @param block The block to coalesce
 * @return A pointer to the first block of the coalesced blocks
 */
void *coalesce(free_block *block) {
    if (block == NULL) {
        return NULL;
    }

    free_block *prev = find_prev(block);
    free_block *next = find_next(block);

    // Coalesce with previous block if it is contiguous.
    if (prev != NULL) {
        char *end_of_prev = (char *)prev + prev->size + sizeof(free_block);
        if (end_of_prev == (char *)block) {
            prev->size += block->size + sizeof(free_block);

            // Ensure prev->next is updated to skip over 'block', only if 'block' is directly next to 'prev'.
            if (prev->next == block) {
                prev->next = block->next;
            }
            block = prev; // Update block to point to the new coalesced block.
        }
    }

    // Coalesce with next block if it is contiguous.
    if (next != NULL) {
        char *end_of_block = (char *)block + block->size + sizeof(free_block);
        if (end_of_block == (char *)next) {
            block->size += next->size + sizeof(free_block);

            // Ensure block->next is updated to skip over 'next'.
            block->next = next->next;
        }
    }

    return block;
}
/**
 * Call sbrk to get memory from the OS
 *
 * @param size The amount of memory to allocate
 * @return A pointer to the allocated memory
 */
void *do_alloc(size_t size) {
    size_t sizet = sizeof(header) + size;
    sizet = (sizet + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
    void *ptr = sbrk(sizet);
    if (ptr == (void *)-1) {
        return NULL;
    }
    header *hdr = (header *)ptr;
    hdr->size = size;  
    hdr->magic = MAGIC_NUMBER;
    return (char *)ptr + sizeof(header);
}


/**
 * Allocates memory for the end user
 *
 * @param size The amount of memory to allocate
 * @return A pointer to the requested block of memory
 */
void *tumalloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    size_t aligned_size = (size + sizeof(header) + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
    size_t block_size = aligned_size;
    free_block *curr = HEAD;
    free_block *prev = NULL;
    while (curr != NULL) {
        if (curr->size >= block_size) {
            if (curr->size >= block_size + sizeof(free_block) + ALIGNMENT) {
                free_block *new_block = (free_block *)((char *)curr + block_size);
                new_block->size = curr->size - block_size;
                new_block->next = curr->next;
                if (prev != NULL) {
                    prev->next = new_block;
                } else {
                    HEAD = new_block;
                }
            } else {
                if (prev != NULL) {
                    prev->next = curr->next;
                } else {
                    HEAD = curr->next;
                }
            }
            header *hdr = (header *)curr;
            hdr->size = size;  
            hdr->magic = MAGIC_NUMBER;
            return (char *)curr + sizeof(header);
        }
        prev = curr;
        curr = curr->next;
    }
    return do_alloc(size);
}

/**
 * Allocates and initializes a list of elements for the end user
 *
 * @param num How many elements to allocate
 * @param size The size of each element
 * @return A pointer to the requested block of initialized memory
 */
void *tucalloc(size_t num, size_t size) {
    if (num > 0 && size > SIZE_MAX / num) {
        return NULL;
    }
    size_t total_size = num * size;
    void *ptr = tumalloc(total_size);
    if (ptr != NULL) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

/**
 * Reallocates a chunk of memory with a bigger size
 *
 * @param ptr A pointer to an already allocated piece of memory
 * @param new_size The new requested size to allocate
 * @return A new pointer containing the contents of ptr, but with the new_size
 */
void *turealloc(void *ptr, size_t new_size) {
    if (ptr == NULL) {
        return tumalloc(new_size);
    }
    if (new_size == 0) {
        tufree(ptr);
        return NULL;
    }
    header *hdr = (header *)((char *)ptr - sizeof(header));
    if (hdr->magic != MAGIC_NUMBER) {
        fprintf(stderr, "Memory corruption detected in turealloc\n");
        abort();
    }
    size_t old_size = hdr->size;
    if (new_size <= old_size) {
        hdr->size = new_size;
        return ptr;
    }
    void *new_ptr = tumalloc(new_size);
    if (new_ptr == NULL) {
        return NULL;
    }
    memcpy(new_ptr, ptr, old_size);
    tufree(ptr);
    return new_ptr;
}

/**
 * Removes used chunk of memory and returns it to the free list
 *
 * @param ptr Pointer to the allocated piece of memory
 */
void tufree(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    header *hdr = (header *)((char *)ptr - sizeof(header));
    hdr->magic = 0;  
    free_block *block = (free_block *)hdr;
    block->size = sizeof(header) + hdr->size;
    free_block *coalesced = coalesce(block);
    if (coalesced == block) {
        coalesced->next = HEAD;
        HEAD = coalesced;
    }
}