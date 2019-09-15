```c
#ifndef FS_FUZZ_FSFUZZER_HH
#define FS_FUZZ_FSFUZZER_HH
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
//파일 정보를 읽어오기 위해 하단의 3개 헤더 추가필요. stat
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/sendfile.h>
#include <set>
#include <vector>
#include <string>
#include <iostream>
#include "mount.hh"
#include "utils.hh"
class fsfuzzer {
  public:
    typedef std::pair<uint64_t, uint64_t> extent_t;
    fsfuzzer(const char *fstype): fstype_(fstype) {
      ;
    }
    ~fsfuzzer() {
      //if (image_path_)
      // free(image_path_);
      // if (image_buffer_)
      // munmap(image_buffer_, image_size_);
    }

    virtual void fix_checksum() {}									//체크섬 게산 함수
    virtual void fix_general_checksum() {}								//체크섬 게산 함수(general)
    virtual void compress(const char *in_path, void *buffer, const char *meta_path = NULL) {}		//압축
    virtual void decompress(const void *meta_buffer, size_t meta_len, bool checksum = true) {}		//압축해제
    virtual void general_decompress(const void *meta_buffer, size_t meta_len, bool checksum = true) {}	//압축해제(general)


	/*함수명 : general_compress
	파라미터 : const char *in_path (압축할 이미지가 있는 경로)
		  void *buffer	
		  const char *meta_path = NULL
	설명 : 

	*/
    void general_compress(const char *in_path, void *buffer, const char *meta_path = NULL) {		//압축(general)
        
        void *zero;
        struct stat st;
        bool generate_meta_image = meta_path != NULL;
        stat(in_path, &st);				//파일의 정보를 읽어오는 함수로, st라는 구조체에 파일의 상태가 저장된다. 파일의 link, uid, gid size 등을 알 수 있다.
        image_size_ = st.st_size;			//이미지 사이즈
        block_size_ = 64;
        block_count_ = image_size_ / block_size_;	//블럭의 갯수 : 이미지크기/64
        
        zero = malloc(block_size_);				//블록 사이즈 만큼 메모리 할당( malloc(64) )
        memset(zero, 0, sizeof(zero));				// 메모리 0으로 64블록 사이즈 만큼 초기화.
        
        int in_image_fd = open(in_path, O_RDONLY);				//이미지 fd 생성
        if (in_image_fd < 0)		
            FATAL("[-] image %s compression failed.", in_path);
        
        image_buffer_ = buffer;							//이미지를 읽어들일 버퍼 생성
        if (read(in_image_fd, image_buffer_, image_size_) != image_size_) {	//C언어 read 함수로 파일을 읽음. image_buffer_에 저장.
            perror("compress");
            FATAL("[-] image %s compression failed.", in_path);
        }
        
        close(in_image_fd);							
        std::set<uint64_t> meta_blocks;							//메타데이터 블럭들 변수 선언.
        for (uint64_t i = 0; i < block_count_; i++) {					
            if (memcmp((char *)image_buffer_ + i * block_size_, zero, block_size_))	//현재 이미지 버퍼에 있는 블록의 값이 모두 0이 아닌 경우 
                meta_blocks.insert(i);							//현재 인덱스 값을 meta_blocks에 저장.
        }
        int meta_image_fd = -1;
        if (generate_meta_image) {							//meta_path 가 있는경우.
            meta_image_fd = open(meta_path, O_CREAT | O_RDWR | O_TRUNC, 0666);		//메타데이터 이미지를 읽어들이기 위한 fd 생성.
            if (meta_image_fd < 0)			
                FATAL("[-] image %s compression failed.", in_path);	
        }
        if (!release_metadata(meta_blocks, meta_image_fd, true))			//
            FATAL("[-] image %s compression failed.", in_path);
        
        if (generate_meta_image)
            close(meta_image_fd);
        
        print_metadata();
    }

	/*함수명 : sync_to_file
	  파라미터 : out_path 포인터
	  설명 : 
	
	*/
    void sync_to_file(const char *out_path) {
      int fd = open(out_path, O_CREAT | O_RDWR | O_TRUNC, 0666);
      if (write(fd, image_buffer_, image_size_) != image_size_)
        FATAL("[-] image sync to file %s failed.", out_path);
      close(fd);
    }

    

	/* 함수명 : release_metadata
	파라미터 :std::set<uint64_t> &meta_blocks (메타데이터 블럭들)
		 int meta_image_fd		 (메타데이터를 읽어들이기 위한 fd)
		 bool in_block			 (블럭)
	
	*/
    bool release_metadata(std::set<uint64_t> &meta_blocks, int meta_image_fd, bool in_block) {
      std::set<uint64_t>::iterator it = meta_blocks.begin();

      do {
        extent_t extent;
        extent.first = in_block ? (*it) * block_size_ : (*it);
        extent.second = block_size_;
        uint64_t cur_offset = extent.first;

        for (it++; it != meta_blocks.end(); it++) {

          if (cur_offset + block_size_ == (in_block ? (*it) * block_size_ : (*it))) {
            extent.second += block_size_;
            cur_offset += block_size_;
          } else {
            break;
          }
        }
        
        metadata_.push_back(extent); 									// 벡터의 맨 뒤로 metaData를 집어 넣는다. 

        if (meta_image_fd > 0) {
          if (write(meta_image_fd, (char *)image_buffer_ + extent.first, extent.second) != extent.second)
            return false;
        }
      } while (it != meta_blocks.end());
      return true;
    }
    void print_metadata() {
      for (auto extent : metadata_)
        printf("offset: 0x%lx size: 0x%lx\n", extent.first, extent.second);
    }
   private:
      
    const char *fstype_;
   protected:
    // std::set<uint64_t> metadata_blocks;
    std::vector<extent_t> metadata_;
    uint32_t block_size_;
    uint32_t block_count_;
    size_t image_size_;
    // char *image_path_;
    void *image_buffer_;
};
#endif
```


