/*
该文件为安全服务器设计的头文件
该文件主要定义了策略库的各个数据结构以及向对象管理器提供的策略查询接口
具体的初始化、策略加载、策略监听以及策略查询等模块正在编码中，还未完成
*/


#include <linux/kernel.h>
#include <linux/vmalloc.h>
#define  HASH_MAX_LENGTH  499 ;

//安全策略库数据结构设计
struct policydb{
	struct te_avtab *te_avtab;
	int te_avtab_size;	  /*哈希表的大小，通常为素数*/
	int te_avtab_use;     /*已使用的哈希表项的数目*/
	int te_policy_num;	  /*已加载TE策略条数*/

	struct wl_avtab *wl_avtab;
	int wl_avtab_size;
	int wl_avtab_use;
	int wl_policy_num;

	struct sub_dom_map *sub_dom_map;
	int sub_dom_map_size;
	int sub_dom_map_use;
	int sdmap_policy_num;

	struct obj_type_map *obj_type_map;
	int obj_type_map_size;
	int obj_type_map_use;
	int otmap_policy_num;
	

};



struct te_avtab{
	struct te_node **te_node;
};
struct te_node{
	struct te_avtab_key *key;
	struct te_avtab_datum *datum;
	struct te_node *next;
};
struct te_avtab_key{
	uint32_t source_type;
	uint32_t target_type;
	uint32_t target_class
};
struct te_avtab_datum{
	uint32_t permission;
};




struct sub_dom_map{
	struct sdmap_node **sdmap_node;
};
struct sdmap_node {
	struct sdmap_key *key;
	struct sdmap_datum *datum;
	struct sdmap_node *next;
};
struct sdmap_key{
	char *sub_name;
};
struct sdmap_datum{
	uint32_t sub_domain;
};



struct obj_type_map{
	struct objtype_node **objtype_node;
};
struct objtype_node{
	struct objtype_key *key;
	struct objtype_datum *datum;
	struct objtype_node *next;
};
struct objtype_key{
	char *obj_name;
};
struct objtype_datum{
	uint32_t obj_type;
};
/* void initial_obj_type_map(struct obj_type_map *obj_type_map){
	for(int i= 0;i<HASH_MAX_LENGTH;++i){
		objtype_node[i] = NULL;
	}
} */



struct wl_avtab_node {		/*白名单策略结点以及以下的两种映射结点，结构同TE策略结点类似，结构体各项含义可从变量的名字推断，故不赘述*/
	struct wl_avtab_key *key;
	struct wl_avtab_datum *datum;
	struct wl_avtab_node *next;
};
struct wl_avtab_key {
	char *source_name;
	char *target_name;
	uint32_t target_class;
};
struct wl_avtab_datum {
	uint32_t permission;
};
struct wl_avtab{
	struct wl_avtab_node **wl_avtab_node;
};
/* void initial_wl_avtab(struct *wl_avtab){
	for(int i= 0;i<HASH_MAX_LENGTH;++i){
		wl_avtab_node[i] = NULL;
	}
} */
