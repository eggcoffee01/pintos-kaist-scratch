/* file.c: Implementation of memory backed file object (mmaped object). */
#include "vm/vm.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */

static bool
lazy_load_mmap (struct page *page, void *aux) {
	struct load_aux *l = aux;

	file_seek(l->file, l->ofs);

	if(file_read(l->file, page->frame->kva, l->page_read_bytes) == NULL){
		palloc_free_page(page->frame->kva);
		return false;
	}

	memset(page->frame->kva + l->page_read_bytes, 0, l->page_zero_bytes);
	pml4_set_dirty(thread_current()->pml4, page->va, true);
	return true;
}
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	
	ASSERT (pg_ofs (addr) == 0);
	ASSERT (offset % PGSIZE == 0);
	uint64_t ret_addr = (uint64_t)addr;
	void * upage = addr;
	size_t file_len = file_length(file);

	while (length > 0) {
		size_t page_read_bytes = file_len < PGSIZE ? file_len : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct load_aux *aux = malloc(sizeof (struct load_aux));
		aux->file = file;
		aux->page_read_bytes = page_read_bytes;
		aux->page_zero_bytes = page_zero_bytes;
		aux->ofs = offset;
		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, lazy_load_mmap, aux))
		{
			free(aux);
			return false;
		}
		
		/* Advance. */
		file_len -= PGSIZE;
		length -= PGSIZE;
		offset += page_read_bytes;
		upage += PGSIZE;
	}
	
	return (void*)ret_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}