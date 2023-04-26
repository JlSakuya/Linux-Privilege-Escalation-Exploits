# Conquering a Use-After-Free in nf_tables: Detailed Analysis and Exploitation of CVE-2022-32250"

## Introduction
This article is a summarization of the research I recently conducted on `CVE-2022-32250`. 
Some (but not all) of my analysis and the process of exploiting the vulnerability were done live and can be found [here](https://www.youtube.com/watch?v=McaJoyoHWVA&list=PLIT_LTJ-NAyevg0Rb_5iV6uN7KX6uhc-_).

My research sprung up from the [write-up](https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/) by [theori.io](https://theori.io). I found their article extremely insightful and perfect for those who seek an overview of the vulnerability and the way it is exploited. Kudos to them!

In this write-up, I will be providing an in-depth look into the vulnerability and the way it is exploited.

As this is a Netfilter vulnerability I recommend reading my [article](https://ysanatomic.github.io/netfilter_nf_tables/) that provides an introduction to the inner workings of `nf_tables`. However, I will try to cover everything you need to know.

## Table of Contents
1. [Background](#background)
	+ [Sets](#sets)
	+ [Lookup Expression](#lookup)
2. [The Vulnerability](#vulnerability)
	+ [Root Cause](#rootcause)
3. [Exploitation](#exploitation)
	+ [Requirements](#requirements)
	+ [Leaking a heap address](#heapaddr)
		- [Method of Exploitation](#heapaddrmethod)
		- [Searching for a primitive](#primitive)
			- [struct user_key_payload](#user_key_payload)	
	+ [Defeating KASLR](#defeatingkaslr)
		- [Technique](#technique)
		- [Leaking an address](#leaking)
		- [Summarizing the KASLR leak process](#summarizingkaslr)
	+ [Escalating via a modprobe_path overwrite](#escalating)
		+ [Method of Exploitation](#escalatingmethod)
		+ [Overwriting modprobe_path](#overwritingmodprobe)
4. [Proof-of-Concept](#poc)
5. [Closing Remarks](#closing)

## Background <a name="background"></a>
Before we take a look at the root cause we need to look at some background information that is needed to understand the vulnerability.

### Sets <a name="sets"></a>
In `nf_tables` are utilized the so-called **Sets**. The scope of their usage is vast but if we are to *extremely* simplify and generalize them - they are a fancy key-value store that sometimes acts just as a list.

A quick example of set usage is: Imagine you had a list of ports (22, 80, 443). If you want to drop all the packets that come on that port you would add those ports in a set and then use an `nft_lookup` expression to check if the incoming packet's port number is part of the set - and if so drop it.

```c
/**
 * 	struct nft_set - nf_tables set instance
 *
 *	@list: table set list node
 *	@bindings: list of set bindings
 *	@table: table this set belongs to
 *	@net: netnamespace this set belongs to
 * 	@name: name of the set
 *	@handle: unique handle of the set
 * 	@ktype: key type (numeric type defined by userspace, not used in the kernel)
 * 	@dtype: data type (verdict or numeric type defined by userspace)
 * 	@objtype: object type (see NFT_OBJECT_* definitions)
 * 	@size: maximum set size
 *	@field_len: length of each field in concatenation, bytes
 *	@field_count: number of concatenated fields in element
 *	@use: number of rules references to this set
 * 	@nelems: number of elements
 * 	@ndeact: number of deactivated elements queued for removal
 *	@timeout: default timeout value in jiffies
 * 	@gc_int: garbage collection interval in msecs
 *	@policy: set parameterization (see enum nft_set_policies)
 *	@udlen: user data length
 *	@udata: user data
 *	@expr: stateful expression
 * 	@ops: set ops
 * 	@flags: set flags
 *	@genmask: generation mask
 * 	@klen: key length
 * 	@dlen: data length
 * 	@data: private set data
 */
struct nft_set {
	struct list_head		list;
	struct list_head		bindings;
	struct nft_table		*table;
	possible_net_t			net;
	char				*name;
	u64				handle;
	u32				ktype;
	u32				dtype;
	u32				objtype;
	u32				size;
	u8				field_len[NFT_REG32_COUNT];
	u8				field_count;
	u32				use;
	atomic_t			nelems;
	u32				ndeact;
	u64				timeout;
	u32				gc_int;
	u16				policy;
	u16				udlen;
	unsigned char			*udata;
	/* runtime data below here */
	const struct nft_set_ops	*ops ____cacheline_aligned;
	u16				flags:14,
					genmask:2;
	u8				klen;
	u8				dlen;
	u8				num_exprs;
	struct nft_expr			*exprs[NFT_SET_EXPR_MAX];
	struct list_head		catchall_list;
	unsigned char			data[]
		__attribute__((aligned(__alignof__(u64))));
};
```
Here it is important to note that expressions can be added to sets in `exprs` and to note the `bindings` linked list.

### Lookup Expression <a name="lookup"></a>
We already mentioned the existence of the `nft_lookup` expression... But what does it do?
The **lookup** expression is used to perform *lookups* into sets to check if a key or a value is present in the set. 

Essentially in the example we provided after you set up your set with ports on which you want to drop packets, you will set up a lookup expression to perform the check on the incoming packets.

```c
struct nft_lookup {
	struct nft_set			*set;
	u8				sreg;
	u8				dreg;
	bool				invert;
	struct nft_set_binding		binding;
};
```
The parameter `set` holds a pointer to the set in which the lookup is going to be performed. `sreg` holds the register index where the **key** that we are looking up is going to be loaded from and `dreg` is the register index where **value** will be stored after the lookup if the key exists.
The final member is `binding`.
```c
struct nft_set_binding {
	struct list_head		list;
	const struct nft_chain		*chain;
	u32				flags;
};
```
Each lookup expression has a binding which contains a pointer to the `nft_chain` to which it belongs (if it belongs to a chain). It also has a *head* to a linked list. All of the expressions that look up into a set are in a linked list with each other (and the *set*) through their `bindings` (and the set's `bindings` member). 

So if we have two lookup expressions `lookup1` and `lookup2` that look up into a set called `set1` they would all be in a linked list.
```c
/* In case needed for clarity:
set1.bindings.next = lookup1.binding
lookup1.binding.next = lookup2.binding
lookup2.binding.next = set1.bindings

lookup2.binding.prev = lookup1.binding
lookup1.binding.prev = set1.bindings
set1.bindings.prev = lookup2.binding
*/
```


## The Vulnerability <a name="vulnerability"></a>
> A use-after-free vulnerability was found in the Linux kernel's Netfilter subsystem in net/netfilter/nf_tables_api.c. This flaw allows a local attacker with user access to cause a privilege escalation issue.

### Root Cause <a name="rootcause"></a>
The problem arises when we add an `nft_lookup` expression to a set. To add a lookup expression to a set you have to use the `NFT_MSG_NEWSET` callback that calls the function `nf_tables_newset`. 
```
nf_tables_newset
	nft_set_elem_expr_alloc
		nft_expr_init
```
`nf_tables_newset` calls `nft_set_elem_expr_alloc` which calls `nft_expr_init`.

Let's take a deeper look at the `nft_expr_init` function.
```c
static struct nft_expr *nft_expr_init(const struct nft_ctx *ctx,
                      const struct nlattr *nla)
{
    struct nft_expr_info expr_info;
    struct nft_expr *expr;
    struct module *owner;
    int err;

    err = nf_tables_expr_parse(ctx, nla, &expr_info); 
    if (err < 0)
        goto err1;

    err = -ENOMEM;
    expr = kzalloc(expr_info.ops->size, GFP_KERNEL); // GFP_KERNEL space 
    if (expr == NULL)
        goto err2;

    err = nf_tables_newexpr(ctx, &expr_info, expr); // [1]
		// if the full intiatialization of the expression to a table: failed	
    if (err < 0) 
        goto err3; // free *expr

    return expr;
err3:
    kfree(expr);
err2:
    owner = expr_info.ops->type->owner;
    if (expr_info.ops->type->release_ops)
        expr_info.ops->type->release_ops(expr_info.ops);

    module_put(owner);
err1:
    return ERR_PTR(err);
}
```
At `[1]` it calls the function `nf_tables_newexpr` to fully initialize an expression. If that fails it frees the expresion.
```c
static int nf_tables_newexpr(const struct nft_ctx *ctx,
                 const struct nft_expr_info *expr_info,
                 struct nft_expr *expr)
{
    const struct nft_expr_ops *ops = expr_info->ops;
    int err;

    expr->ops = ops; // sets the ops of the expression to those expr_info->ops;
    if (ops->init) {
				// does intialization
        err = ops->init(ctx, expr, (const struct nlattr **)expr_info->tb); // [2]
        if (err < 0)
            goto err1;
    }

    return 0;
err1:
    expr->ops = NULL;
    return err;
}
```
At `[2]` we see that the expression specific `ops->init` function gets called and if it fails it returns the error to the caller - `nft_expr_init`. 
Each type of expression has its own `nft_expr_ops` defined. Let's take a look at the `ops` of the lookup expression as we are talking about it.
```c
static const struct nft_expr_ops nft_lookup_ops = {
	.type		= &nft_lookup_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_lookup)),
	.eval		= nft_lookup_eval,
	.init		= nft_lookup_init,
	.activate	= nft_lookup_activate,
	.deactivate	= nft_lookup_deactivate,
	.destroy	= nft_lookup_destroy,
	.dump		= nft_lookup_dump,
	.validate	= nft_lookup_validate,
	.reduce		= nft_lookup_reduce,
};
```
Here we can see that `ops->init` of the lookup expression is `nft_lookup_init`.
```c
static int nft_lookup_init(const struct nft_ctx *ctx,
               const struct nft_expr *expr,
               const struct nlattr * const tb[])
{
    struct nft_lookup *priv = nft_expr_priv(expr); 
    u8 genmask = nft_genmask_next(ctx->net);
    struct nft_set *set;
    u32 flags;
    int err;

    if (tb[NFTA_LOOKUP_SET] == NULL ||
        tb[NFTA_LOOKUP_SREG] == NULL)
        return -EINVAL;

		// sets up nft_set
    set = nft_set_lookup_global(ctx->net, ctx->table, tb[NFTA_LOOKUP_SET],
                    tb[NFTA_LOOKUP_SET_ID], genmask);
    if (IS_ERR(set))
        return PTR_ERR(set);

    ...
		// gets the flags 
    priv->binding.flags = set->flags & NFT_SET_MAP;

		// attempts to bind the expression to the set
    err = nf_tables_bind_set(ctx, set, &priv->binding); // [1]
    if (err < 0)
        return err;

    priv->set = set; 
    return 0;
}
int nf_tables_bind_set(const struct nft_ctx *ctx, struct nft_set *set,
               struct nft_set_binding *binding)
{
    struct nft_set_binding *i;
    struct nft_set_iter iter;

    if (set->use == UINT_MAX)
        return -EOVERFLOW;

    if (!list_empty(&set->bindings) && nft_set_is_anonymous(set))
        return -EBUSY;

    ...

bind:                          
    binding->chain = ctx->chain;
    list_add_tail_rcu(&binding->list, &set->bindings);
    nft_set_trans_bind(ctx, set);
    set->use++;

    return 0;
}
```
At `[1]` we can see that it calls the function `nf_tables_bind_set` to bind the expression to the set. In `nf_tables_bind_set` we can see that it fails if the bindings are not empty but the set is anonymous. So for the binding to succeed the set that we are performing the **lookup** at shouldn't be anonymous.
> If we want a set to be non-anonymous we can just not set the anonymous flag when creating it. 

We already established that when adding an expression to a set the `nft_expr_init` function gets called by `nft_set_elem_expr_alloc`. Let's take a look at it.

```c
struct nft_expr *nft_set_elem_expr_alloc(const struct nft_ctx *ctx,
                     const struct nft_set *set,
                     const struct nlattr *attr)
{
    struct nft_expr *expr;
    int err;

    expr = nft_expr_init(ctx, attr); // [1]
    if (IS_ERR(expr))
        return expr;

    err = -EOPNOTSUPP;
    if (!(expr->ops->type->flags & NFT_EXPR_STATEFUL)) // [2]
        goto err_set_elem_expr;

    if (expr->ops->type->flags & NFT_EXPR_GC) {
        if (set->flags & NFT_SET_TIMEOUT)
            goto err_set_elem_expr;
        if (!set->ops->gc_init)
            goto err_set_elem_expr;
        set->ops->gc_init(set);
    }

    return expr;

err_set_elem_expr:
    nft_expr_destroy(ctx, expr); // [3]
    return ERR_PTR(err);
}

void nft_expr_destroy(const struct nft_ctx *ctx, struct nft_expr *expr)
{
    nf_tables_expr_destroy(ctx, expr);
    kfree(expr);
}

static void nf_tables_expr_destroy(const struct nft_ctx *ctx,
                   struct nft_expr *expr)
{
    const struct nft_expr_type *type = expr->ops->type;

    if (expr->ops->destroy)
        expr->ops->destroy(ctx, expr); // [4]
    module_put(type->owner);
}
```
At `[1]` we can see the call to `nft_expr_init` that eventually results in the **lookup** expression being bound to the set. At `[2]` we can see that a check is performed to see if the flag `NFT_EXPR_STATEFUL` is present and if not it calls `nft_expr_destroy`. `nft_expr_destroy` itself calls `nf_tables_expr_destroy` which calls the expression-specific `ops->destroy` function.

Let's look at the lookup expression's destroy function - `nft_lookup_destroy`.
```c
static void nft_lookup_destroy(const struct nft_ctx *ctx,
                   const struct nft_expr *expr)
{
    struct nft_lookup *priv = nft_expr_priv(expr);

    nf_tables_destroy_set(ctx, priv->set); // [1]
}

void nf_tables_destroy_set(const struct nft_ctx *ctx, struct nft_set *set)
{
    if (list_empty(&set->bindings) && nft_set_is_anonymous(set)) // [2]
        nft_set_destroy(ctx, set); 
}
```
At `[1]` in `nft_lookup_destroy` a call is performed to `nf_tables_destroy_set` to destroy the set it bounded to **if possible**. At `[2]` a check is performed to see if it is safe to destroy the set - if the bindings are empty and the set is anonymous. However, the set won't be destroyed if it is named or if has any bindings - and it will always have at least a single binding because the expression got bound to it prior to being destroyed.

So the problem is that in the function `nft_set_elem_expr_alloc` the call to `nft_expr_init` is performed **before** it is checked if the expression has the `NFT_EXPR_STATEFUL` flag. This means that if an expression without the stateful flag is passed, the expression will be initiated fully first and bound to the set before it gets destroyed because the flag is missing. 

So what happens when we pass an expression without `NFT_EXPR_STATEFUL`? The expression will get bound to the set before the expression gets destroyed. However, the set that it is bound to won't get destroyed because its bindings are not empty. And as we see in the functions above there is no handling in this case. The expression already got bound to the set and it will stay bound. A pointer to it will remain in the `bindings` linked list of the set even though the expression got destroyed and its memory got freed. So now the linked list at `set->bindings` contains a pointer to freed memory. A Use-After-Free arises.

## Exploitation <a name="exploitation"></a>
The way this vulnerability is exploited depends on the kernel version of the target. 
If the target is pre-version `5.14` there is just `kmalloc-<n>` (`KMALLOC_NORMAL`) slab caches. After this version, there are two different types of caches - for accounted objects and unaccounted ones. Accounted objects are allocated using the flag `GFP_KERNEL_ACCOUNT` and they go to `kmalloc-cg-<n>` (`KMALLOC_CGROUP`) caches. Unaccounted objects use the old flag `GFP_KERNEL` and go into the legacy `kmalloc-<n>` caches. This is important as in later versions where separate caches are present for accounted and unaccounted objects, the `nft_lookup` expression is still unaccounted for, i.e. gets allocated with the flag `GFP_KERNEL`. Therefore in order to exploit the Use-After-Free vulnerability the objects that we are going to use as primitives must also be allocated with the `GFP_KERNEL` flag in versions that use the new `kmalloc-cg-<n>` caches.

My goal was to write a version-agnostic exploit. To do that I only used objects that are still allocated with `GFP_KERNEL` even on newer versions. This way the exploit is viable with the older and newer cache implementations.

The exploit can be divided into three essential stages - leaking a heap address, leaking KASLR and overwriting `modprobe_path` to escalate our privileges.

> It's important to note that the exploit was tested on 5.12.0 as this was what I had laying around. Version 5.12 is before kmalloc-cg-\<n> caches were introduced. 

### Requirements <a name="requirements"></a>
To be able to exploit the vulnerability you need `CAP_NET_ADMIN`. That shouldn't be a problem in most cases as that capability can be obtained in a `user+net` namespace. So our only requirement is that we can create `user` and `network` namespaces.

### Leaking a heap address <a name="heapaddr"></a> 
It is essential to be able to leak a heap address as we are going to need one to successfully fool the kernel and bypass some security protections in the KASLR leaking stage but more on that later. Let's now look into how we are going to leak the heap address.

We already established that the Use-After-Free occurs because we are left with a pointer to the binding of an `nft_lookup` expression that has been freed. 
Every expression in `nf_tables` is of the abstract type `nft_expr`.
```c
/**
 *	struct nft_expr - nf_tables expression
 *
 *	@ops: expression ops
 *	@data: expression private data
 */
struct nft_expr {
	const struct nft_expr_ops	*ops; // nft_lookup_ops in our case (8 bytes)
	unsigned char			data[] // this holds the nft_lookup object 
		__attribute__((aligned(__alignof__(u64)))); // aligned 8 bytes
};

struct nft_lookup {
	struct nft_set			*set; // @8 (8 bytes) 
	u8				sreg; // @16 (1 byte)
	u8				dreg; // @17 (1 byte)
	bool				invert; // @18 (also takes at east a byte)
	struct nft_set_binding		binding; // @24 (16 bytes)
	// @24 because 8-byte aligned because first member is a pointer
};

struct nft_set_binding {
	struct list_head		list; // @24; (2 pointers - 16 bytes)
	const struct nft_chain		*chain; // @40 (8 bytes)
	u32				flags; // @48 (4 bytes)
};

```
Here the `data` in `nft_expr` holds `struct nft_lookup`. The size of `struct nft_expr` whenever it holds an expression of type `nft_lookup` is `0x34 = 52 bytes`. This indicates allocation in `kmalloc-64`. 
Therefore we are looking for primitives also in `kmalloc-64` that are being allocated with `GFP_KERNEL` on versions with separate slab caches.

#### Method of Exploitation <a name="heapaddrmethod"></a>
In order to leak a heap address we have to trigger the writing of a heap address into the freed memory object. That is trivially done by adding two `nft_lookup` expressions one after the other that target the same set. Let's call those two lookup expressions `Object 1` and `Object 2`.
As we already established, all the lookup expressions that target a certain set are in a linked list through their `bindings`. 
If we add a lookup expression without the `NFT_EXPR_STATEFUL` flag it will get bound to the set through its `binding` and then freed - this is our `Object 1`. Now if we add a second lookup expression (`Object 2`) that targets the same set it will also be added to the same linked list. Therefore now the set and both of these lookup expressions are in a linked list together. This means that the `binding.next` pointer of `Object 1` is going to hold the address of the `binding` of `Object 2`. However, as we know `Object 1` got freed prior to the allocation of `Object 2`. Therefore if we allocate an object we control (`Fake Object 1`) in the same space in memory where `Object 1` got previously allocated now we have control over the memory where `Object 1` is supposed to be. Consequently when `Object 2` gets added the kernel thinks it is writing its address to the `binding.next` of `Object 1` but in reality, it is writing it somewhere in the scope of `Fake Object 1` that we control and can read from. 

Important to mention here that the object we choose to allocate as `Fake Object 1` must be `kmalloc-64` and be allocated with `GFP_KERNEL`.

Summarizing:
+ Allocate lookup expression (`Object 1`) without the `NFT_EXPR_STATEFUL` flag targetting  `Set 1`. It will get bound to the set and then freed.
+ Initiate an object under our control (`Fake Object 1`) that will get allocated at the same memory allocation where `Object 1` was allocated.
+ Add another lookup expression (`Object 2`) that also targets `Set 1`. Now `Object 1.binding` and `Object 2.binding` are in a linked list. However `Object 1` doesn't exist anymore so actually the address of `Object 2.binding` is written in the scope of `Fake Object 1`.
+ Read `Fake Object 1` and leak the address of `Object 2`.

Now we established what our methodology for the heap leak is. Now it is time we find a primitive that we can use for `Fake Object 1`. 

#### Searching for a primitive <a name="primitive"></a>
Objects used in the POSIX message queue filesystem have commonly been used as primitives due to the high degree of control we possess over them. For example, the `msg_msg` could have been a candidate here - we can control its size and reading memory with it is easy.
```c
/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list; 
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
```
However, the header of `msg_msg` is six 8-byte words or 48 bytes. This means that `binding.next` won't be overlapping with the readable section (the actual message section) but with `m_type`.
```c
/* ipc/msgutil.c */
static struct msg_msg *alloc_msg(size_t len)
{
	struct msg_msg *msg;
	struct msg_msgseg **pseg;
	size_t alen;

	alen = min(len, DATALEN_MSG);
	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL_ACCOUNT); // [1]
	...
	return msg;

out_err:
	free_msg(msg);
	return NULL;
}
```
At `[1]` we can see that `msg_msg` gets allocated with the flag `GFP_KERNEL_ACCOUNT` and that is another reason why it is not viable as a primitive.

##### struct user_key_payload <a name="user_key_payload"></a>
A viable primitive was found in the face of `user_key_payload`. It belongs to the kernel's key management facility. It holds the payload for keys of type `user` and `logon`. 
```c
/* include/keys/user-type.h */
struct user_key_payload {
	struct rcu_head	rcu;		/* RCU destructor */ // @0 - 16 bytes
	unsigned short	datalen;	/* length of this data */ // @16 - 2 bytes
	char		data[] __aligned(__alignof__(u64)); /* actual data */ // @24
};

/* include/linux/types.h
 * struct callback_head - callback structure for use with RCU and task_work
 * @next: next update requests in a list
 * @func: actual update function to call after the grace period.
 * ...
 */
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head
```
Let's take a look at the function responsible for allocating `user_key_payload`.
```c
/* security/keys/user_defined.c */
int user_preparse(struct key_preparsed_payload *prep)
{
	struct user_key_payload *upayload;
	size_t datalen = prep->datalen;

	if (datalen <= 0 || datalen > 32767 || !prep->data)
		return -EINVAL;

	upayload = kmalloc(sizeof(*upayload) + datalen, GFP_KERNEL); // [1]
	if (!upayload)
		return -ENOMEM;

	/* attach the data */
	prep->quotalen = datalen;
	prep->payload.data[0] = upayload;
	upayload->datalen = datalen;
	memcpy(upayload->data, prep->data, datalen);
	return 0;
}
EXPORT_SYMBOL_GPL(user_preparse);
```
At `[1]` we can see that the allocation is performed with `GFP_KERNEL` flag therefore it is a viable primitive. Let's take a look at how it overlaps with `nft_expr[nft_lookup]`.
```txt
nft_expr that holds nft_lookup | user_key_payload
=================================================
0x0: *ops                      | rcu_head.next
0x8: *set                      | rcu_head.func
0x10: sreg/dreg/invert         | rcu_head.datalen
0x18: binding.next             | data[0]
0x20: binding.prev             | data[8]
```
We can see here that `binding.next` of `nft_lookup` overlaps with `data[0]` of `user_key_payload`. This suits our purposes as the value of `binding.next` will be written in `data[0:8]`.
 
So now our exploitation strategy is:
+ Add a lookup expression (`Obj 1`) so it gets bound and then freed.
+ Add a user key (`Fake Obj 1`) with payload size such that it would get allocated in `kmalloc-64` and where the UAF'd expression was.
+ Add another lookup expression (`Obj 2`) that looks up into the same set. This would populate `binding->next` of `Obj 1`. However `Obj 1` got UAF'd so the address of `Obj 2` will get written into the data portion of `Fake Obj 1` that is of type `user_key_payload`.
+ Read `Fake Obj 1` and leak the address of `Obj 2`.


### Defeating KASLR <a name="defeatingkaslr"></a>
After leaking a heap address our next goal is to leak a `.text` address to defeat `KASLR`. 
During this, stage we are going to be leveraging the [message queue subsystem](https://man7.org/linux/man-pages/man7/mq_overview.7.html) of the kernel as well as the [in-kernel key management and retention facility](https://man7.org/linux/man-pages/man7/keyrings.7.html). 

#### Technique <a name="technique"></a>
The technique we are going to use to defeat KASLR is explained in detail in my article [Abusing RCU callbacks with a Use-After-Free read to defeat KASLR](https://ysanatomic.github.io/abusing_rcu_callbacks_to_defeat_kaslr/). 

The technique in a nutshell as I introduce it in the article is:
> The technique is possible when we control two objects allocated next to each other in the same slab cache. We must be able to read out-of-bounds through the first object while the second object must have a rcu_head as its first member.
If we make a call to update the second object the kernel will call call_rcu which will populate rcu_head->func(). Then if we can read OOB through the first object into the second object’s rcu_head without sleeping (as to not let the kernel execute rcu_head->func() which will free the memory and maybe zero it out if sensitive) we will be able to leak the address in rcu_head->func() therefore defeating KASLR.

#### Leaking an address <a name="leaking"></a>
We are going to trigger an allocation of an expression that gets UAF'd (`Object 1`). We make a call to the message queue subsystem to create a message queue. This will result in the allocation of a `posix_msg_tree_node` object (`Fake Object 1`). The `posix_msg_tree_node` has to be allocated at the same location where `Object 1` that got UAF'd was allocated.
```c
struct posix_msg_tree_node {
    struct rb_node      rb_node; // of size 0x18 = 24 bytes
    struct list_head    msg_list; // @24 (is 16 bytes)
    int         priority; // @40
};

struct rb_node {
    unsigned long  __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
```
The `msg_head` of `poxis_msg_tree_node` is at offset `24 = 0x18` bytes from the start - same as the `list_head` of the `nft_set_binding` of the `nft_lookup` expression. 
```txt
nft_expr that holds nft_lookup | posix_msg_tree_node
====================================================
0x0: *ops                      | _rb_parent_color
0x8: *set                      | *rb_right
0x10: sreg/dreg/invert         | *rb_left
0x18: binding.next             | msg_list.next
0x20: binding.prev             | msg_list.prev
```
This would mean that the address of the binding of any new lookup expression will be written at offset `0x18` of the `posix_msg_tree_node` which is `msg_list.next`. This gives us a primitive with which we can fool the kernel that an object is a message (`struct msg_msg`) and fetch it - potentially leaking any addresses and pointers stored in the object. 
> msg_msg gets allocated with GFP_KERNEL_ACCOUNT and therefore couldn't be in the same slab cache (KMALLOC_NORMAL) as our nft_lookup expressions. However, that doesn't stop us from fooling the kernel that an object that is in a KMALLOC_NORMAL cache is actually of type msg_msg - which is exactly what we are doing.

```c
struct msg_msg {
	struct list_head m_list; // @0
	long m_type; // @16
	size_t m_ts;		/* message text size */ // @24
	struct msg_msgseg *next; // @32
	void *security; // @40
	/* the actual message follows immediately */
	/* the size can be up to 16 bytes while staying under 64 */
};
```
Looking at `msg_msg` we can see that the `list_head` of the object is right at the beginning of the object. This is in contrast to `nft_expr[nft_lookup]` where it is at offset 24 bytes. This is significant as the kernel believes that the address at `posix_msg_tree_node.msg_list.next` will be that of a `msg_msg` object (where the `list_head` is at the beginning). Instead, the kernel will find the address of an expression's `binding`. Therefore the kernel will calculate incorrectly where the object starts resulting in an out-of-bounds read. This leaves us with an OOB read primitive that can be used to leak up to 16 bytes from the next slab object satisfying the first condition of the *technique*.
(Take a look at the table for clarity)

```txt
nft_expr[nft_lookup]   | msg_msg
======================================================
0x0: *ops              | 
0x8: *set              |
0x10: sreg/dreg/invert | 
0x18: binding.next     | m_list.next
0x20: binding.prev     | m_list.prev
0x28: ...              | m_type
0x30: ...              | m_ts
0x38: ...              | *next
======== Going outside the 64 byte slab object =======
0x40:                  | *security
0x48:                  | msg[0]
0x50:                  | msg[1]
```

As we already established: the second lookup expression (let it be called `Object 2`) we allocate will be treated as the first message in a message queue. However, to have a successful read via the message queue system - we need to be able to set the parameters of `msg_msg`. In order to do that we would need to UAF `Object 2` and allocate another object in its place (`Fake Object 2`).
```c
struct user_key_payload {
	struct rcu_head	rcu;		/* RCU destructor */
	unsigned short	datalen;	/* length of this data */
	char		data[] __aligned(__alignof__(u64)); /* actual data */
};
```
The type of `Fake Object 2` will be once again `user_key_payload` as it gets allocated with  `GFP_KERNEL` and we can use it to write the parameters of the fake `msg_msg` by writing to `data`. This way we can set the `m_type` and `m_ts` of the fake message (we also have to write valid pointers into `m_list->next` and `mlist->prev`).

```txt
nft_expr[nft_lookup]   | user_key_payload | msg_msg
======================================================
0x0: *ops              | rcu.next         | 
0x8: *set              | rcu.func         |
0x10: sreg/dreg/invert | datalen          |
0x18: binding.next     | data[0]          | m_list.next
0x20: binding.prev     | data[1]          | m_list.prev
0x28: ...              | data[2]          | m_type
0x30: ...              | data[3]          | m_ts
0x38: ...              | data[4]          | *next
======== End of Object 2 ; Object 3 follows ==========
0x8:                   |                  | *security
0x10:                  |                  | msg[0]
0x18:                  |                  | msg[1]
```
Here the first column represents the `nft_lookup` expression that gets UAF'd. The second column is the object that gets allocated over the object that got UAF'd while the third column shows how the kernel is going to treat the object (as a `msg_msg` object that is offset by `24 = 0x18` bytes).

Whenever a call to fetch a message is made the function `do_mq_timedreceive` gets called. At the end of the function as the `msg_msg` object is about to get freed a call to free `msg_msg->security` is made as a security measure - so in order for the message fetch to succeed there must be a valid heap address at offset `40=0x28` bytes. Therefore we need to take measures in ensuring that there is indeed a heap address at that location. We must also note that due to the nature of the OOB read the `*security` pointer would be at offset `64=0x40` bytes - right at the beginning of the next slab object as you can see above (this is due to the 24-byte offset read).

We are going to leak KASLR through the object we allocate right under `Object 2 / Fake Object 2`. A perfect object for this task is once again... `user_key_payload` - the main character of our write-up. 
The first member of `user_key_payload` is a `rcu_head/callback_head`.
```c
struct callback_head {
	struct callback_head *next; // @0
	void (*func)(struct callback_head *head); // @8 rcu_head->func 
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head
```
The first member of the `callback_head` is a pointer (`callback_head->next`) that will be treated as `msg_msg->security` and the second member is a function pointer that will overlap with `msg[0]`. Therefore if we make a call to read the message we will be able to read that function pointer and leak KASLR.

However, there is an issue: both `callback_head->next` and `callback_head->func` will be *null* by default. In order to populate them we must make a call to change the payload (`Object 3`). This is due to the way RCU callbacks work - when a call is made to change an RCU-protected object `call_rcu` is invoked.
> The call_rcu() API is a callback form of synchronize_rcu().  Instead of blocking, it registers a function and argument which are invoked after all ongoing RCU read-side critical sections have completed. This callback variant is particularly useful in situations where it is illegal to block or where update-side performance is critically important.

The function at `callback_head->func` will be executed by the kernel when it is safe to do so. In the case of updating a `user_key_payload` the callback function will be `user_free_payload_rcu` which will free and zero out `Object 3`.
```c
static void user_free_payload_rcu(struct rcu_head *head)
{
	struct user_key_payload *payload;

	payload = container_of(head, struct user_key_payload, rcu);
	kfree_sensitive(payload);
}
```
So leaking `callback_head->func` is essentially a race against the kernel - trying to read it and leak it before the kernel zeroes it out.

I go over the technique in more detail in my article [Abusing RCU callbacks with a Use-After-Free read to defeat KASLR](https://ysanatomic.github.io/abusing_rcu_callbacks_to_defeat_kaslr/).

#### Summarizing the KASLR leak process: <a name="summarizingkaslr"></a>
1. Allocate a `nft_lookup` expression (`Object 1`) such that it causes a UAF.
2. Initiate a message queue in order to allocate a `posix_msg_tree_node` (`Fake Object 1`) at the location of `Object 1`.
3. Spray `user_key_payload` objects and then randomly free a few to create a bunch of gaps in the cache so `Object 2` gets allocated in between them.
4. Add a new `nft_lookup` expression (`Object 2`) such that it causes a UAF. The address of this expression's `binding` (which's address is `[Object 2] + 0x18`) will be written into the `msg_list->next` of the `poxis_msg_tree_node`. Now if a message is fetched from the message queue the kernel will target `[Object 2] + 0x18` to get the message (`msg_msg`). We also hope that this object would have been allocated such that the object immediately below it is a `user_key_payload` (and this is why we spray a lot of them in step 3).
5. Allocate a `user_key_payload` (`Fake Object 2`) at the location of `Object 2`. Write into the payload the parameter values we want our fake `msg_msg` at `[Object 2] + 0x18` to have. We write values for `m_list->next`, `m_list->prev`, `m_type` and `m_ts`.
6. Mass update all the `user_key_payload` objects to populate the `rcu_head` members.
7. Make a call to fetch the first message from a message queue. This should leak a kernel address, defeating KASLR (if we won the race against the kernel to leak `rcu_head->func` before it got zeroed out). 


### Escalating via a modprobe_path overwrite <a name="escalating"></a>
An easy way to achieve Local Priviliege Escalation is by overwriting the `modprobe_path` of the kernel.
`modprobe` is used to load kernel modules from userspace. A common usage of it is to load the necessary module needed to execute a binary with an uncommon binary header. 
The location of `modprobe` is stored in the `modprobe_path` symbol. It is possible for us to overwrite `modprobe_path` as it is stored in the `.data` segment (which is read/write and variables stored in there can be altered at run time).

#### Method of Exploitation <a name="escalatingmethod"></a>
Our goal is to write `modprobe_path` to an executable that we control - let's call that `fake_modprobe`. 

As we already established `modprobe` is executed in order to load a kernel module needed to handle the execution of a binary of an uncommon type. We can set up a `trigger` binary with an unknown binary header which when executed will force the kernel to execute `modprobe` in order to attempt to load an appropriate kernel module to handle `trigger`. But instead of `modprobe` being run, `fake_modprobe` will be executed with kernel privileges. 

The `fake_modprobe` executable can be a simple script that changes the ownership of a `get_shell` executable to `root` and sets its SUID and GUID bits. In this case, `get_shell` just does:
```
setuid(0);
setgid(0);
system("/bin/sh");
```
The process summarized:
- Overwrite `modprobe_path` to `/path/to/fake_modprobe`
- Execute a `trigger` binary with an unknown binary header.
- The kernel executes `fake_modprobe` in an attempt to load the needed modules to execute `trigger` which instead changes the ownership and permissions of `get_shell`.
- Execute `get_shell` to escalate privileges.

#### Overwriting modprobe_path <a name="overwritingmodprobe"></a>
When a call to fetch a message is made the function `do_mq_timedreceive` gets executed which itself makes a call to `msg_get` to get the highest priority message from a queue.
```c
static inline struct msg_msg *msg_get(struct mqueue_inode_info *info)
{
	struct rb_node *parent = NULL;
	struct posix_msg_tree_node *leaf;
	struct msg_msg *msg;

try_again:
	/*
	 * During insert, low priorities go to the left and high to the
	 * right.  On receive, we want the highest priorities first, so
	 * walk all the way to the right.
	 */
	parent = info->msg_tree_rightmost;
	if (!parent) {
		if (info->attr.mq_curmsgs) {
			pr_warn_once("Inconsistency in POSIX message queue, "
				     "no tree element, but supposedly messages "
				     "should exist!\n");
			info->attr.mq_curmsgs = 0;
		}
		return NULL;
	}
	leaf = rb_entry(parent, struct posix_msg_tree_node, rb_node);
	if (unlikely(list_empty(&leaf->msg_list))) {
		pr_warn_once("Inconsistency in POSIX message queue, "
			     "empty leaf node but we haven't implemented "
			     "lazy leaf delete!\n");
		msg_tree_erase(leaf, info);
		goto try_again;
	} else {
		msg = list_first_entry(&leaf->msg_list,
				       struct msg_msg, m_list);
		list_del(&msg->m_list); // [1] <---------------------
		if (list_empty(&leaf->msg_list)) {
			msg_tree_erase(leaf, info);
		}
	}
	info->attr.mq_curmsgs--;
	info->qsize -= msg->m_ts;
	return msg;
}
```
At `[1]` we can see that `list_del` is used to remove the message (`msg_msg`) from the linked list of messages in the queue. 

`list_del` deletes a list entry by making the prev/next entries point to each other.
```c
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev; // [1]
	WRITE_ONCE(prev->next, next); // [2]
}
```
The instruction at `[1]` will write `prev` into `next+0x8` while the instruction at `[2]` will write `next` into `prev`.

We introduced in the **KASLR bypass** section of this write-up a way to fool the kernel that an object is a `msg_msg` - with the ability to set the members of the fake `msg_msg` to the values we want.
```txt
nft_expr[nft_lookup]   | user_key_payload | msg_msg
======================================================
0x0: *ops              | rcu.next         | 
0x8: *set              | rcu.func         |
0x10: sreg/dreg/invert | datalen          |
0x18: binding.next     | data[0]          | m_list.next
0x20: binding.prev     | data[1]          | m_list.prev
0x28: ...              | data[2]          | m_type
0x30: ...              | data[3]          | m_ts
0x38: ...              | data[4]          | *next
=====================================================
0x8:                   |                  | *security
0x10:                  |                  | msg[0]
0x18:                  |                  | msg[1]
```
We can use a `user_key_payload` object to set up the fake `msg_msg` exactly how we want it - including setting `m_list.next` and `m_list.prev` to any value we want. We can therefore take advantage of the `list_del` function - letting it write to `modprobe_path` for us. To do that we would need to set `m_list.prev` to the value we want `modprobe_path` to hold and set `m_list.next` to `modprobe_path - 0x7` (as it writes `prev` into `next+0x8` and we want to counteract this offsetting while still leaving the `/` at the beginning of the existing `modprobe_path`). 

An interesting caveat though is that the value we write to `m_list.prev` (which is going to serve as the path written in `modprobe_path`) must be a valid address at which the kernel has to be able to write -  this however is not a problem as we leaked the heap base earlier and we can make such an address-like path that is valid.
```c
// excerpt from my Proof-of-Concept
uint64_t modprobe_path = heap_base + 0x2f706d74; // 0x2f706d74 = tmp/ (but little endian)
```
This would result into `modprobe_path` being changed in `/tmp/<2 bytes of entropy>\xff\xff<rest of original modprobe_path>` (the 2 bytes of entropy here belong to the heap base we leaked).

Now it is a matter of placing the fake modprobe at this path and executing the `trigger` binary.

## Proof-of-Concept <a name="poc"></a>
The PoC is available at [https://github.com/ysanatomic/CVE-2022-32250-LPE](https://github.com/ysanatomic/CVE-2022-32250-LPE).

```txt
# ./exploit
[*] CVE-2022-32250 LPE Exploit by @YordanStoychev

uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)
[*] Setting up user+network namespace sandbox

uid=0(root) gid=0(root) groups=0(root)

[+] STAGE 1: Heap leak
[*] Socket is opened.
[*] Table table1 created.
[*] Socket is opened.
[*] Table table2 created.
[*] Socket is opened.
[*] Table table3 created.
[*] Set created
[*] Set with UAF'd expression created
[*] Set with UAF'd expression created
[&] heap_addr: 0xffff91d97f89f398
[&] heap_base: 0xffff91d900000000

[+] STAGE 2: KASLR bypass
[*] Set created
[*] Set with UAF'd expression created
[*] Set with UAF'd expression created
[&] kaddr: 0xffffffff9f54bef0
[&] kbase: 0xffffffff9f000000

[+] STAGE 3: modprobe_path overwrite
[*] Set created
[*] Set with UAF'd expression created
[*] Set with UAF'd expression created

[*] STAGE 4: Escalation
[*] Setting up the fake modprobe...
[*] modprobe_path: /tmp/ّprobe
[*] Setting up the shell...
[*] Triggering the modprobe...
[*] Executing shell...
/ #
```

## Closing Remarks <a name="closing"></a>
Analysing and Exploiting this vulnerability was lots of fun. Initially, I planned to do everything from analysing it to making the exploit live on stream but I started doing more and more off-stream and then I just finished it up off-stream. I might make one last stream/video where I go over the final exploit in detail.

Took me some time to sit down and finish up the write-up - but better late than never.

If you have any questions feel free to hit me up on Twitter or by email.
