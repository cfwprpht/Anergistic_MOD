// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "main.h"
#include "config.h"
#include "elf.h"
#include "emulate.h"
#include "gdb.h"

struct ctx_t _ctx;
struct ctx_t *ctx;

static int gdb_port = -1;
static const char *elf_path = NULL;
static const char *eid_segm = NULL; 
static const char *root_key = NULL;

void dump_regs(void)
{
	u32 i;

	printf("\nRegister dump:\n");
	printf(" pc:\t%08x\n", ctx->pc);
	for (i = 0; i < 128; i++)
		printf("%.3d:\t%08x %08x %08x %08x\n",
				i,
				ctx->reg[i][0],
				ctx->reg[i][1],
				ctx->reg[i][2],
				ctx->reg[i][3]
				);
}

void dump_ls(void)
{
	FILE *fp;

	printf("dumping local store to " DUMP_LS_NAME "\n");
	fp = fopen(DUMP_LS_NAME, "wb");
	fwrite(ctx->ls, LS_SIZE, 1, fp);
	fclose(fp);
}

void fail(const char *a, ...)
{
	char msg[1024];
	va_list va;

	va_start(va, a);
	vsnprintf(msg, sizeof msg, a, va);
	perror(msg);

#ifdef FAIL_DUMP_REGS
	dump_regs();
#endif

#ifdef FAIL_DUMP_LS
	dump_ls();
#endif

	gdb_deinit();
	exit(1);
}

static void usage(void)
{
	printf("usage: anergistic -g1234 per_console_key eid_segment filename.elf\n");
	exit(1);
}

static void parse_args(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "g:")) != -1) {
		switch(c) {
			case 'g':
				gdb_port = strtol(optarg, NULL, 10);
				root_key = argv[2];
	      eid_segm = argv[3];
	      elf_path = argv[4];
				break;
			default:
				printf("Unknown argument: %c\n", c);
				usage();
		}
	}

	if (optind != argc - 3)
		usage();

  if (argv[4] == NULL){
	     root_key = argv[1];
	     eid_segm = argv[2];
	     elf_path = argv[3];
	  };
}

int main(int argc, char **argv)
{
	u32 done;
	memset(&_ctx, 0x00, sizeof _ctx);
	ctx = &_ctx;
	parse_args(argc, argv);
	
	//Remove old output.
	printf("\n");
	printf("Removing old output...");
	system("rm -f out.bin, eid_tmp");
	printf("done\n");
	
	//Copy eid segment to a temporary file	  
	printf("\n");
  printf("Copy EID segment to temporary file...");
  
  FILE *fs, *ft;
  int ch;
	
	ft = fopen("eid_tmp", "wb+");    
	fs = fopen(eid_segm, "rb");
	
	if (fs == NULL){
	  printf("Fail to open file %s", eid_segm);
	  return 0;
	} 
	    
	while (1){
	  ch = fgetc(fs);
	  if (ch == EOF) break;
	  else fputc(ch, ft);
	} 
	     
	fclose(fs);
	fclose(ft);
  
	printf("done\n");

#if 0
	
	//Set module parameters.
	//PU DMA area start address.
	//Dummy to make the module happy.
	ctx->reg[3][0] = 0xdead0000;
	ctx->reg[3][1] = 0xbeef0000;
	
	//PU DMA area size.
	//ctx->reg[4][0] = 0x80;
	ctx->reg[4][1] = 0x80;
	
	//PU EID area start address (first param).
	//Dummy to make the module happy.	
	ctx->reg[5][0] = 0xcafe0000;
	ctx->reg[5][1] = 0xbabe0000;
	
	//First param size.
	//ctx->reg[6][0] = 0x860;
	ctx->reg[6][1] = 0x860;
	
#endif

	ctx->ls = malloc(LS_SIZE);
	if (ctx->ls == NULL)
		fail("Unable to allocate local storage.");
	memset(ctx->ls, 0, LS_SIZE);
	
	//Write EID master key (to start of LS).
	u8 eid_mkey[48] = {0};                                                 //initialize eid_mkey to 0	
	int i, rc;	
	printf("\n");
	printf("loading master-key...");
	FILE *fp = fopen(root_key, "rb");                                      //open the desired key in read binary mode
	
	if (fp == NULL){
	  printf("Failed to open file %s\n", root_key);
	  return 0;
	}
	
	for (i = 0; (rc = getc(fp)) != EOF && i < 48; eid_mkey[i++] = rc) { }	 //set the bytes of choosen key to eid_mkey
	fclose(fp);
	
	if (i == 48){                                      //check if eid_mkey hase 48 bytes and print to screen
	  printf("done\n");
	  puts("the bytes of choosen master key are;\n");     
	  printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", eid_mkey[0], eid_mkey[1], eid_mkey[2], eid_mkey[3], eid_mkey[4], 
	  eid_mkey[5], eid_mkey[6], eid_mkey[7], eid_mkey[8], eid_mkey[9], eid_mkey[10], eid_mkey[11], eid_mkey[12], eid_mkey[13], eid_mkey[14], eid_mkey[15]);  
	  printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", eid_mkey[16], eid_mkey[17], eid_mkey[18], eid_mkey[19], eid_mkey[20], 
	  eid_mkey[21], eid_mkey[22], eid_mkey[23], eid_mkey[24], eid_mkey[25], eid_mkey[26], eid_mkey[27], eid_mkey[28], eid_mkey[29], eid_mkey[30], eid_mkey[31]);
	  printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", eid_mkey[32], eid_mkey[33], eid_mkey[34], eid_mkey[35], eid_mkey[36], 
	  eid_mkey[37], eid_mkey[38], eid_mkey[39], eid_mkey[40], eid_mkey[41], eid_mkey[42], eid_mkey[43], eid_mkey[44], eid_mkey[45], eid_mkey[46], eid_mkey[47]);          
	  memcpy(ctx->ls, eid_mkey, sizeof(eid_mkey));    //finally copy eid_mkey to start of LS
	  printf("\n");                      
	}	
	else{
	  printf("An error occured while setting %s as master-key\n", root_key);
	  return 0;
	}
	  
#if 1
	wbe64(ctx->ls + 0x3f000, 0x100000000ULL);
	wbe32(ctx->ls + 0x3f008, 0x10000);
	wbe32(ctx->ls + 0x3e000, 0xff);
#endif

	if (gdb_port < 0) {
		ctx->paused = 0;
	} else {
		gdb_init(gdb_port);
		ctx->paused = 1;
		gdb_signal(SIGABRT);
	}

	elf_load(elf_path);

	done = 0;

	while(done == 0) {

		if (ctx->paused == 0)
			done = emulate();

		// data watchpoints
		if (done == 2) {
			ctx->paused = 0;
			gdb_signal(SIGTRAP);
			done = 0;
		}
		
		if (done != 0) {
			printf("emulate() returned, sending SIGSEGV to gdb stub\n");
			ctx->paused = 1;
			done = gdb_signal(SIGSEGV);
		}

		if (done != 0) {
#ifdef STOP_DUMP_REGS
			dump_regs();
#endif
#ifdef STOP_DUMP_LS
			dump_ls();
#endif
		}

		if (ctx->paused == 1)
			gdb_handle_events();
	}
	printf("emulate() returned. we're done!\n");
	dump_ls();
	free(ctx->ls);
	gdb_deinit();
	return 0;
}
