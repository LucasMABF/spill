# Development Journal

This project is part of the BDL (Bitcoin Dev Launchpad) study program.
This journal serves to track my thinking process and progress while working
on this proof-of-concept implementation of Spillman channels.

Here I record ideas, learnings, questions, and design decisions
that come up during development.

## Note about AI use

I often use AI to:

- revise my text
- search for information, looking out for inaccuracies
- refactor, review, and adapt my code to best practices and improved implementations

## 2026-01-12

- Researched Spillman channels.

Main resources used:
- [bitcoin wiki](https://en.bitcoin.it/wiki/Payment_channels#Spillman-style_payment_channels)
- [reddit post](https://www.reddit.com/r/Bitcoin/comments/cc9psl/technical_a_brief_history_of_payment_channels/)
- [ark blog](https://blog.arklabs.xyz/bitcoin-virtual-channels/)

Here's my current understanding of the subject:

First, it helps to clarify what is meant by a "channel".
In Bitcoin, a channel usually refers to a way of transferring value between
participants without broadcasting every transaction to the Bitcoin network.

This is done while preserving the trustless and secure nature of Bitcoin. Channels
are useful because on-chain transactions can be slow, expensive,
and contribute to network congestion.

Spillman channels are unidirectional payment channels that
predate the ones used in the Lightning Network.
Unidirectional means that there is a payer and a payee,
and the flow of value always goes in the direction of the payee.

They allow one party (Alice) to make a series of payments to another
party (Bob) without broadcasting every transaction to the Bitcoin network.

The simplest and earliest implementation works roughly as follows:

Alice wants to make a series of small payments to Bob.

1. Alice creates a funding transaction that locks her funds in a 2-of-2
multisig output between herself and Bob, and asks Bob to sign it first. 

2. Before broadcasting the funding transaction, Alice creates a refund transaction
that spends the funding output back to herself after a locktime,
and asks Bob to sign it.

3. Once Bob has signed the refund transaction, Alice is guaranteed that she can
recover her funds even if Bob disappears or refuses to cooperate.

4. Only after the refund transaction is fully signed does Alice sign and broadcast
the funding transaction.

5. After the funding transaction is confirmed, Alice can start making payments to Bob.
Each payment is represented by a new transaction that spends the funding output,
paying a certain amount to Bob and returning the remaining balance to Alice.

6. Before the refund transaction locktime, Bob should broadcast the latest
transaction in order to settle the channel on-chain and avoid Alice getting
the full refund.

There is also a more modern and simpler way to implement Spillman channels,
using Bitcoin Script and the more recent locktime functionality. This approach avoids
some potential issues present in the earlier construction, such as transaction
malleability (although this was later solved, so both approaches can work correctly).

This construction is enabled by the opcode OP_CHECKLOCKTIMEVERIFY.
With this approach, a separate refund transaction is no longer required.

It works as follows:

1. Alice creates a funding transaction that locks her funds in an output
with a script that can be spent either by Alice alone, after a specified locktime
in the future, or by a 2-of-2 multisig between Alice and Bob. 

2. Both Alice and Bob sign the funding transaction, and it is then
broadcast to the network.

3. Payments work in the same way as before. Alice creates and sends Bob
new signed transactions that spend the funding output,
each one paying more to Bob than the previous one.

4. Bob can broadcast the latest transaction to settle the channel on-chain
and claim the funds owed to him.

This method simplifies the refund path of the channel setup while preserving the same
security properties.

This is how I intend to implement Spillman channels in this library.

- Attended a presentation about
[rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin), which led me to decide
to build my implementation on top of this library, as it provides Bitcoin primitives,
transaction types, and PSBT (Partially Signed Bitcoin Transaction) support
that fit well with my use case.

## 2026-01-13

- Researched rust-bitcoin, read some documentation and the cookbook.

## 2026-01-14

- Started implementing the library and made some design decisions about the
workflow and public interface.

Here's what I've come up with:

Since this library isn't meant to be a wallet, it shouldn't handle private keys
or signing. That responsibility stays with the client. This keeps the library
focused on providing tools for facilitating channel creation and management while
giving clients flexibility and control. To support this, the library produces PSBTs
and returns then to the client, so they can manage signing, additional inputs,
outputs and fees.

I chose to expose `Channel` and `ChannelParams` types to separate the
static parameters from the channel's dynamic state, which allows
`ChannelParams` to be cloned and reused. This also makes sense, as a `Channel`
should only exist once a funding transaction has been created and broadcast, 
which is handled using `ChannelParams`.

These types define a channel and provide methods to create and interact with it
on the network. The methods create the transactions necessary for this,
and provide them as PSBTs, allowing the user to finalize and broadcast them.
All methods act as helpers, as there still is a lot to be done by the user,
but they take care of the heavy lifting specific to the channel's protocol.

## 2026-01-15

- Completed the main library functionality and created an example demonstrating
client-side usage.

This is a crude, hardcoded example of how the library might be used. It can
create a channel, make payments, and close it. It also demonstrates how to
handle the refund payment.

- Tested on Signet

First, I created and broadcast a funding transaction:

> `f74d5a8db33c04678412c12e8fb5a9397a719ff46322fb92a3adf006a277e5c4`

Then I made two payments and broadcast the last one,
which amounted to the sum of both:

> `e763872c3dba0768fed5ce82201e0a9f33369535394b16120f8773a5becdcf69`


Now that it's at least functional, I plan to do some refactoring, fix
error handling, improve the API, and make the library easier to use.
After that, I could add some new features. It might be a good idea
to try implementing it using Taproot, and allowing for different setups.

