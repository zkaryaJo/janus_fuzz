JANUS에서 추가한 헤더파일
```C
#include <sys/sendfile.h>
#include <mutator_wrapper.hpp>
```

```C
int main(int argc, char** argv) {
```

JANUS에서 추가된 옵션
```C
      case 'u': /* CPU# */
	        if (sscanf(optarg, "%u", &cpu_id) != 1)
	          PFATAL("Invalid CPU#");
	        break;

	  case 'g': /* image path */
		image_file = optarg;
		fsfuzz_mode = 1;
        OKF("[fs-fuzz] target image path: %s", image_file);
		break;
	
      case 'k': /* kernel fuzz mode */
		OKF("We are now fuzzing kernel");
		fsfuzz_mode = 1;
		break;
	 
	  case 'b': /* shm name */
		shm_name = optarg;
		fsfuzz_mode = 1;
        OKF("[fs-fuzz] shm name to store image buffer: %s", shm_name);
		break;
	  
	  case 's': /* wrapper.so path */
		wrapper_file = optarg;
		fsfuzz_mode = 1;
        OKF("[fs-fuzz] target wrapper (.so) path: %s", wrapper_file);
		break;
	  
	  case 'e': /* seed */
		seed_file = optarg;
		fsfuzz_mode = 1;
        OKF("[fs-fuzz] seed image path: %s", seed_file);
		break;

	  case 'y' : /* syscall input dir */

		syscall_in_dir = optarg;
		fsfuzz_mode = 1;
        OKF("[fs-fuzz] syscall input directory: %s", syscall_in_dir);
		break;


```
JANUS 에서 추가한 함수
```C
setup_wrapper()
write_execs_file()
load_seed_image()
load_syscalls()

```
JANUS 에서 추가한 변수
```C
static u32 cpu_id = -1;
static u32 fsfuzz_mode = 0;
static u32 meta_size = 0;
u32 fsfuzz_queued;
u32 _step = 1;
EXP_ST u8 *image_file,	  		/* for fs fuzzing					  */
	  *wrapper_file,	  	/* for fs fuzzing					  */
	  *seed_file,	  		/* for fs fuzzing 					  */
	  *syscall_in_dir,         	/* for fs fuzzing					  */
	  *shm_name;	 		/* for fs fuzzing					  */

u32 orig_queued_with_cov; // 
```

1) JANUS에선 Trimming을 하지 않는다.

```C
  /************
   * TRIMMING *
   ************/

   // fs-fuzz: we cannot arbitrary trim for now...

  if (!fsfuzz_mode && !dumb_mode && !queue_cur->trim_done) {


```

fuzz_one 스케쥴링 확

```C
static u8 fuzz_one(char** argv) {

  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;
  u32 orig_queued_with_cov;

  u8  ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

  if (queue_cur->depth > 1) return 1;

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }

  if (not_on_tty) {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

  /* 테스트 케이스를 메모리에 매핑. */
  fd = open(queue_cur->fname, O_RDONLY);
  len = queue_cur->len;
  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  close(fd);

  out_buf = ck_alloc_nozero(len);
  subseq_tmouts = 0;
  cur_depth = queue_cur->depth;

  if (queue_cur->cal_failed) {
    if (queue_cur->cal_failed < CAL_CHANCES) {  
    	CALIBRATION 수행
    }
  }

  memcpy(out_buf, in_buf, len);

  /* 스코어 계산. */
  orig_perf = perf_score = calculate_score(queue_cur);
  goto havoc_stage;
```

havoc 스테이지 !!
```C

havoc_stage:

  stage_cur_byte = -1;

  if (!splice_cycle) {

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;

  } else {

    static u8 tmp[32];
    perf_score = orig_perf;
    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

  }

```

