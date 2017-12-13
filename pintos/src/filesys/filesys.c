#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;
char * get_name(const char * path);
struct dir * extract_parent_dir(char * path);
static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  cache_init();
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  write_back();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir) 
{
  disk_sector_t inode_sector = 0;
  struct dir *dir = extract_parent_dir(name);
  char *f_name = get_name(name);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, isdir)
                  && dir_add (dir, f_name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  free(f_name);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir = extract_parent_dir(name);
  char *f_name = get_name(name);
  struct inode *inode = NULL;

  if(strlen(name) == 0)
    return NULL;

  if (dir != NULL)
  {
    if(strcmp(f_name, ".") == 0 || (is_root(dir) && strlen(f_name) == 0))
    {
      free(f_name);
      return (struct file *) dir;
    }
    else if(strcmp(f_name, "..") == 0)
    {
      if(!get_parent_dir(dir, &inode))
      {
        free(f_name);
        return NULL;
      }
    }
    else
    {
      dir_lookup(dir, f_name, &inode);
    }
  }
  dir_close (dir);

  if(inode == NULL)
  {
    free(f_name);
    return NULL;
  }

  if(inode_isdir(inode))
  {
    free(f_name);
    return (struct file *) dir_open(inode);
  }
  free(f_name);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir = extract_parent_dir(name);
  char *f_name = get_name(name);
  bool success = dir != NULL && dir_remove (dir, f_name);
  dir_close (dir); 
  free(f_name);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

/****** functions to parse path string ******/

/* get the name from the path */
char *
get_name(const char * path)
{
  char path_copy[strlen(path)+1];
  strlcpy(path_copy, path, strlen(path)+1);
  char *curr, *prev="", *save_ptr;
  for(curr = strtok_r(path_copy, "/", &save_ptr); curr != NULL; curr = strtok_r(NULL, "/", &save_ptr))
  {
    prev = curr;
  }

  char *name = malloc(strlen(prev)+1);
  strlcpy(name, prev, strlen(prev)+1);
  return name;
}

/* get the directory of the file in the path for easy path parsing */
struct dir *
extract_parent_dir(char * path)
{
  char path_copy[strlen(path)+1];
  strlcpy(path_copy, path, strlen(path)+1);

  char *curr, *next, *save_ptr;
  struct dir *curr_dir;

  // if absolute path or curr_dir is not set yet (then curr_dir should be root)
  if(path_copy[0] == '/' || thread_current()->curr_dir == NULL)
  {
    curr_dir = dir_open_root();
  }

  // otherwise open the current directory
  else
  {
    curr_dir = dir_reopen(thread_current()->curr_dir);
  }

  next = NULL;
  curr = strtok_r(path_copy, "/", &save_ptr);

  if(curr)
  {
    next = strtok_r(NULL, "/", &save_ptr);
  }

  /* loop until there is no more token afterwards */
  while(next != NULL)
  {
    // . will not change the directory, so skip.
    if(strcmp(curr, ".") == 0)
    {
      curr = next;
      next = strtok_r(NULL, "/", &save_ptr);
      continue;
    }
    else
    {
      struct inode *inode;
      // .. -> get parent directory
      if(strcmp(curr, "..") == 0)
      {
        if(!get_parent_dir(curr_dir, &inode))
          return NULL;
      }
      else
      {
        if(!dir_lookup(curr_dir, curr, &inode))
          return NULL;
      }

      // ignore inode that is not directory
      if(!inode_isdir(inode))
        inode_close(inode);
      else
      {
        dir_close(curr_dir);
        curr_dir = dir_open(inode); // move on to the next directory in path name
      }
    }
    curr = next;
    next = strtok_r(NULL, "/", &save_ptr);
  }

  return curr_dir;
}

