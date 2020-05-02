/**********************************************************************
  Authors: Alexander Bajic and Georg T. Becker
  E-Mail: bajic@me.com

  Description:
  This is a sample implementation of the dPHI protocol. It emulates
  all necessary steps to establish a communication session between
  source and destination. All performed cryptographic operations
  are done just the way a real-world implementation would require.
  Please note that this sample implementaion does not take
  care of any routing. Instead, we assume that a route is given so
  that this program can just perform all the operations as they would
  be done by the intermediate nodes in the course of session
  establishment. Instructions on how to measure performance for various
  methods can be found in the extensive comments in the main method.
  The relevant section starts at around line number 1540.

**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "aes_gcm.h"
#include "sha256_mb.h"
#include "x86intrin.h"

#define DEBUG 0
#define TO_HELPER_NODE 1
#define FIND_MIDWAY 2
#define MIDWAY_REPLY 3
#define HANDSHAKE_TO_D 4
#define REPLY_TO_W 5
#define REPLY_TO_S 6
#define TRANSMISSION_PHASE_TO_D1 7
#define TRANSMISSION_PHASE_TO_D2 8
#define TXT_SIZE 11
#define AAD_SIZE 27
#define TAG_SIZE 16		/* Valid values are 16, 12, or 8 */
#define KEY_SIZE GCM_256_KEY_LEN
#define IV_SIZE  GCM_IV_DATA_LEN
#define VECTOR_LENGTH 12
#define NUM_OF_NODES 24
#define NUM_OF_SIMS 1000000

// declare external functions that will be used later
int curve25519_donna(uint8_t *, const uint8_t *, const uint8_t *);
extern void sha256_ref(uint8_t * input_data, uint32_t * digest, uint32_t len);

// this array serves to save cycle measurement across all simulations
int cVector[NUM_OF_SIMS];

/**************************************************************************
 Following comes the declaration of structs that represent the nodes that
 represent the routing entities in the network, as well as the messages,
 they process (consisting of Header, Vectorelement and Payload)
**************************************************************************/

struct Vectorelement {
  uint8_t iv[IV_SIZE];
  uint8_t ct[TXT_SIZE];
  uint8_t at[TAG_SIZE];
};

struct Header {
  uint8_t sid[16];
  uint8_t status;
  uint8_t pos;
  uint8_t dest[4];
  uint8_t midway[17];
  struct Vectorelement v1[VECTOR_LENGTH];
  struct Vectorelement v2[VECTOR_LENGTH];
};

struct Payload {
  uint8_t iv[IV_SIZE];
  uint8_t ct[12]; /* dest is 4 bytes and nmid is 8 bytes*/
  uint8_t at[TAG_SIZE];
  uint8_t pubKeyS[32];
  uint8_t vectorSafe[2*(VECTOR_LENGTH*(16+TXT_SIZE+TAG_SIZE))];
};

struct Node {
  int id;
  uint8_t address[4];
  uint8_t pubKey[32];
  uint8_t privKey[32];
  uint8_t sessionKey[32];
  uint8_t longTermKey[KEY_SIZE];
  uint8_t nonce[8];
  uint8_t midwaySeed[16];
  uint8_t midwayIv[IV_SIZE];
  uint8_t midwayIv2[IV_SIZE];
  uint8_t midwayIv3[IV_SIZE];
  uint8_t midwayIv4[IV_SIZE];
  uint8_t midwayAt[TAG_SIZE];
  uint8_t origDest[4];
};

/**************************************************************************
 needed for qsort when ordering cVector
**************************************************************************/
int compare( const void* a, const void* b)
{
     int int_a = * ( (int*) a );
     int int_b = * ( (int*) b );

     if ( int_a == int_b ) return 0;
     else if ( int_a < int_b ) return -1;
     else return 1;
}

/**************************************************************************
 TODO
**************************************************************************/
void vectorToByteArray(struct Vectorelement *vector,uint8_t *byteArray)
{
  int offset=0;
  for(int i=0;i<12;i++)
  {
    memcpy(byteArray+offset,vector[i].ct,TXT_SIZE);
    offset=offset+TXT_SIZE;
    memcpy(byteArray+offset,vector[i].iv,IV_SIZE);
    offset=offset+IV_SIZE;
    memcpy(byteArray+offset,vector[i].at,TAG_SIZE);
    offset=offset+TAG_SIZE;
  }
}

/**************************************************************************
 This function calculates the average of the middle quartile of all values
 in the cVector array. The values are sorted and
**************************************************************************/
void cVectorAnalysis(void)
{
  qsort( cVector, NUM_OF_SIMS, sizeof(int), compare );
  int newVSize=NUM_OF_SIMS/4;
  int newVector[newVSize];
  int start=newVSize+(newVSize/2);
  for(int x=start;x<start+newVSize;x++)
  {
    newVector[x-start]=cVector[x];
  }
  long int avg=0;
  for(int i=0;i<newVSize;i++)
  {
    avg=avg+newVector[i];
  }
  printf("AVG of middle quarter: %ld\n",avg/newVSize);
}

/**************************************************************************
 This is a wrapper for sha256 hash generation so that changes to
 implementation do not affect rest of code.
**************************************************************************/
void getHash(uint8_t *buffer,uint8_t *digest, int len)
{
  uint32_t digest32[SHA256_DIGEST_NWORDS];

  sha256_ref(buffer, digest32, len);
  memcpy(digest,digest32,len);
}

/**************************************************************************
 Simplification of structured printing.
**************************************************************************/
void printer(const char *txt, uint8_t * var, int len)
{
  int i;
  printf("%s", txt);
  for (i = 0; i < len;) {
    printf(" %2x", 0xff & var[i++]);
    if (i % 32 == 0)
      printf("\n");
  }
  printf("\n");
}

/**************************************************************************
 This function is used to print the current message's payload if
 DEBUG==1 -> Note, that this highly impacts measured cycles
**************************************************************************/
void payloadprint(struct Payload *payload)
{
  printf("Payload information\n\n");
  printer("  IV:         ", payload->iv, IV_SIZE);
  printer("  CT:         ", payload->ct, 12);
  printer("  AT:         ", payload->at, TAG_SIZE);
  printer("  pubKeyS:    ", payload->pubKeyS, 32);
}

/**************************************************************************
 This function is used to print the current message's header if
 DEBUG==1 -> Note, that this highly impacts measured cycles
**************************************************************************/
void headerprint(struct Header *header)
{
  printf("Header information\n\n");
  printer("  SID:        ", header->sid, 16);
  printer("  status:     ", &(header->status), 1);
  printer("  pos:        ", &(header->pos), 1);
  printer("  dest:       ", header->dest, 4);
  printer("  midway:     ", header->midway, 17);
  printf("  V1\n");
  for (int i=0;i<VECTOR_LENGTH;i++) {
    printf("     %d\n",i);
    printer("        iv:   ", header->v1[i].iv, IV_SIZE);
    printer("        ct:   ", header->v1[i].ct, TXT_SIZE);
    printer("        at:   ", header->v1[i].at, 16);
  }

  printf("  V2\n");
  for (int i=0;i<VECTOR_LENGTH;i++) {
    printf("     %d\n",i);
    printer("        iv:   ", header->v2[i].iv, IV_SIZE);
    printer("        ct:   ", header->v2[i].ct, 16);
    printer("        at:   ", header->v2[i].at, 16);
  }

  printf("\n\n");
}

/**************************************************************************
 This code is taken from the Intel documentation on how to use their
 rdrand with help of inline assembly.
**************************************************************************/
int rdrand64_step (uint64_t *rand)
{
	unsigned char ok;

	asm volatile ("rdrand %0; setc %1"
		: "=r" (*rand), "=qm" (ok));

	return (int) ok;
}

/**************************************************************************
 This function constructs our IV, resorting to rdrand64_step from Intel.
**************************************************************************/
void generateIv(uint8_t * freshIv)
{
  uint64_t rdTest1;
  uint64_t rdTest2;

  rdrand64_step(&rdTest1);
  rdrand64_step(&rdTest2);
  memcpy(freshIv,&rdTest1,8);
  memcpy(freshIv+8,&rdTest2,4);
}

/**************************************************************************
 This function creates public-private key pairs to bootstrap the nodes
 that we use for routing. The quality of these keys and their randomness
 is not important in this toy example. They just need to be different
 across nodes. The generation of these keys is also not part of perfor-
 mance measuring.
 Instructions on how to to use this library taken from
 "https://github.com/agl/curve25519-donna" and "http://cr.yp.to/ecdh.html"
**************************************************************************/
void initPubPriv(struct Node *node)
{
  // there are better sources of randomness but it does not matter for this toy example since it is not part of our measurement!
  for (int u=0;u<32;u++) {
    node->privKey[u]=rand() % 256;
  }
  node->privKey[0] &= 248;
  node->privKey[31] &= 127;
  node->privKey[31] |= 64;

  static const uint8_t basepoint[32] = {9};

  // calling the function from the external library to derive the corresponding public key
  curve25519_donna(node->pubKey, node->privKey, basepoint);
}

/**************************************************************************
 This is just a wrapper for the generation of the session keys based on
 the curve25519_donna library.
**************************************************************************/
void establishSessionKey(struct Node *node1, struct Node *node2)
{
  curve25519_donna(node1->sessionKey, node1->privKey, node2->pubKey);
}

/**************************************************************************
 This function initializes the various nodes with random data. The quality
 of randomnes of longterm keys is not important at this point as we only
 want to have different values within the different nodes.
 Again, this bootstrapping of nodes is not part of our protocol's perfor-
 mance measuring.
**************************************************************************/
struct Node initializeNode(struct Node node,int i)
{
  memset(&node, 0, sizeof node);
  node.id=i;
  // init longTermKey
  for (int u=0;u<KEY_SIZE;u++) {
    node.longTermKey[u]=rand() % 256;
  }
  for (int u=0;u<4;u++) {
    node.address[u]=rand() % 256;
  }

  return node;
}


/**************************************************************************
* In the following are different methods that are used for the different
* phases of the protocol. These may, to a certain degree, be redundant so
* that code could be more compact if we had aimed at proper reuse. Yet, the
* separation into different methods is helpful when attempting to retrace
* what is happening.
**************************************************************************/

/**************************************************************************
 This function marks the start of any communication between source and
 destination. The source sets up the communication request message. This
 relates to "Algorithm 1" in the paper's appendix.
**************************************************************************/
void iAmS(struct Node *node, struct Node *helperNode, struct Node *destNode,struct Header *header,struct Payload *payload,struct Header *headerStored)
{
  /* Quality of nonce irrelevant in toy example.
  Performance of this step is not subject to performance measurement.*/
  for (int i=0;i<8;i++) {
    node->nonce[i]=rand() % 256;
  }

  //ks-M <- ECDH(pubM,privS)
  establishSessionKey(node,helperNode);

  //H.sid <- Hash(pubS)
  uint8_t digest[32];
  getHash(node->pubKey,digest,32);
  memcpy(header->sid,digest,16);

  // now write to payload
  struct gcm_key_data gkey;
  struct gcm_context_data gctx;
  uint8_t pt[12];
  memcpy(pt,destNode->address, 4);
  memcpy(pt+4,node->nonce,8);

  uint8_t *freshIv;
  freshIv = malloc(IV_SIZE);
  generateIv(freshIv);

  aes_gcm_pre_256(node->sessionKey, &gkey);
  aes_gcm_enc_256(&gkey, &gctx, payload->ct, pt, 12, freshIv, header->sid, 16, payload->at, TAG_SIZE);

  memcpy(payload->iv,freshIv,IV_SIZE);
  memcpy(payload->pubKeyS,node->pubKey,32);

  // we conserve information about original destination of s
  memcpy(node->origDest,destNode->address,4);

  // done with payload

  //H.V1 <- random()
  for (int i=0;i<VECTOR_LENGTH;i++) {
    for (int u=0;u<16;u++) {

      if(u<TXT_SIZE){
        header->v1[i].ct[u]=rand() % 256;
      }
      if(u<IV_SIZE){
        header->v1[i].iv[u]=rand() % 256;
      }
      header->v1[i].at[u]=rand() % 256;
    }
  }

  //H.pos <- random(0,l-1)
  header->pos=rand() % 12;

  //H.dest <- M
  memcpy(header->dest,helperNode->address, 4);

  //H.status <- "toHelperNode"
  header->status=TO_HELPER_NODE;

  //Hs <- H
  memcpy(headerStored,header, sizeof *header);
  free(freshIv);
}

/**************************************************************************
 This function covers the forwarding of the message on its way from source
 s to Helper node M. This is the "Maidway Request" and relates to
 "Algorithm 2" in the paper's appendix.
**************************************************************************/
struct Header sToM(struct Header header, struct Node node, struct gcm_key_data gkey, uint8_t *freshIv, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  /* in 'a' the cycle counter at the beginning of this function is stored
  for reference when measuring and storing it again at the end in 'b' */
  a=__rdtsc();

  struct gcm_context_data gctx;
  uint8_t ingres[4], egres[4], pType, posV1, posV2;
  uint8_t myCt[TXT_SIZE];
  uint8_t* rp = malloc(TXT_SIZE * sizeof(uint8_t)); // array to hold the result
  uint8_t tag1[TAG_SIZE];
  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */
  uint8_t cPrev[TXT_SIZE];
  uint8_t posPrev;

  /*
    Now we prepare the data fields for R, these contain:
      ingres  32 bit randomly chosen (fictive)
      egres   32 bit randomly chosen (fictive)
      type     8 bit randomly chosen (irrelevant at this point)
      posV1 is the pos we have from the header
      posV2 should be a value that is obviously bogus (i.e. beyond the length of V2)
  */

  for (int i=0;i<4;i++) {
    ingres[i]=rand() % 256;
    egres[i]=rand() % 256;
  }

  pType=0;
  posV1=header.pos;
  /* the following will generate a number that is beyond the array size,
  so that it is obviously not a valid index and can be detected as such */
  posV2=rand() % 256 + VECTOR_LENGTH;

  if(DEBUG == 1){
    printf("Parameters for R\n\n");
    printer("  ingres:    ", ingres, 4);
    printer("  egres:     ", egres, 4);
    printer("  pType:     ", &pType, 1);
    printer("  posV1:     ", &posV1, 1);
    printer("  posV2:     ", &posV2, 1);
  }

  /* now generate routing entry R by concatenating
  ingres, egres, type, posV1 and posV2 */
  memcpy(rp, ingres, 4 * sizeof(uint8_t));
  memcpy(rp + 4, egres, 4 * sizeof(uint8_t));
  memcpy(rp + 8, &pType, sizeof(uint8_t));
  memcpy(rp + 9, &posV1, sizeof(uint8_t));
  memcpy(rp + 10, &posV2, sizeof(uint8_t));

  if(DEBUG == 1){
    printf("Encryption:\n");
    printer("  generated R:         ", rp, TXT_SIZE);
  }

  // create authentication data and declare tag
  memcpy(myAad, header.sid, 16);
  if (header.pos == 0){
    posPrev=(header.pos + VECTOR_LENGTH -1);
  }
  else{
    posPrev=(header.pos -1);
  }

  memcpy(cPrev, header.v1[posPrev].ct, TXT_SIZE);
  memcpy(myAad + 16, cPrev, TXT_SIZE);

  aes_gcm_enc_256(&gkey, &gctx, myCt, rp, TXT_SIZE, freshIv, myAad, AAD_SIZE, tag1, TAG_SIZE);

  if(DEBUG == 1){
    printer("  generated myCt      :",myCt,TXT_SIZE);
    printer("  generated tag1      :",tag1,TAG_SIZE);
  }

  // now save that stuff to the header an increase pos
  memcpy(header.v1[header.pos].ct, myCt, TXT_SIZE);
  memcpy(header.v1[header.pos].iv, freshIv, IV_SIZE);
  memcpy(header.v1[header.pos].at, tag1, TAG_SIZE);

  // increment position pointer in the header
  header.pos=(header.pos + 1) % VECTOR_LENGTH;

  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
  free(rp);
  return header;
}

/**************************************************************************
 This function handels the processing of the message upon arrival at the
 helper node M. This is still the "Maidway Request" and likewise relates to
 "Algorithm 2" in the paper's appendix.
**************************************************************************/
struct Header iAmHelper(struct Node *node,struct Header header,struct Payload payload, struct gcm_key_data gkey, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  a=__rdtsc();
  uint8_t digest[32];

  //Assert(H.sid == Hash(P.pubS))
  getHash(payload.pubKeyS,digest,32);
  if(DEBUG ==1){
    if(memcmp(header.sid, digest, 16) == 0)
    {
      printf("\033[0;32m");
      printf("M: SID and PubS fit\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("M: SID and PubS do not fit\n");
      printf("\033[0m");
    }
  }

  //generate sessionkey for M
  curve25519_donna(node->sessionKey, node->privKey, payload.pubKeyS);

  //decrypt payload
  struct gcm_context_data gctx;
  aes_gcm_pre_256(node->sessionKey, &gkey);
  uint8_t pt2[12];
  uint8_t tag2[TAG_SIZE];
  aes_gcm_dec_256(&gkey, &gctx, pt2, payload.ct, 12, payload.iv, header.sid, 16, tag2, TAG_SIZE);

  if(DEBUG ==1){
    if(memcmp(payload.at, tag2, TAG_SIZE) == 0){
      printf("\033[0;32m");
      printf("M: auth tags ok\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("M: auth tags not ok\n");
      printf("\033[0m");
    }
  }

  //H.dest <- d
  memcpy(header.dest,pt2,4);

  //H.status <- "findMidway"
  header.status=FIND_MIDWAY;

  //H.midway <- nmid
  memcpy(header.midway,pt2+4,8);

  uint8_t position=header.pos;
  if (position == 0){
    position=position+VECTOR_LENGTH;
  }

  position=(position-1)%VECTOR_LENGTH;
  header.pos=position;

  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);

  return header;
}

/**************************************************************************
 This function handels the processing of the message on its way back to the
 source s. Yet, it does NOT cover the operations performed by Midway node W
 that is ultimately traversed on the way from M to s. This will be covered
 in a seperate function.

 This function relates to parts of "Algorithm 3" and all of "Algorithm 4"
 in the paper's appendix. (Alg3 and Alg4 are similar except for the
 handling of what happens at Midway node W).
 The same function here is used to cover "Algorithm 10" from the paper's
 appendix, as it, in principle, does the same thing: forwarding back to s.
**************************************************************************/
struct Header mToS(struct Header header, struct Node *node, struct gcm_key_data gkey, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  a=__rdtsc();

  struct gcm_context_data gctx;
  uint8_t tag2[TAG_SIZE];
  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */
  memcpy(myAad, header.sid, 16 * sizeof(uint8_t));
  uint8_t cPrev[TXT_SIZE];
  uint8_t posPrev;
  if (header.pos == 0){
    posPrev=(header.pos + VECTOR_LENGTH -1) % VECTOR_LENGTH;
  }
  else{
    posPrev=(header.pos -1) % VECTOR_LENGTH;
  }

  memcpy(cPrev, header.v1[posPrev].ct, TXT_SIZE);
  memcpy(myAad + 16, cPrev, TXT_SIZE * sizeof(uint8_t));

  uint8_t pt2[TXT_SIZE];
  aes_gcm_dec_256(&gkey, &gctx, pt2, header.v1[header.pos].ct, TXT_SIZE, header.v1[header.pos].iv, myAad, AAD_SIZE, tag2, TAG_SIZE);
  if(DEBUG == 1){
    printf("Decryption:\n");
    printer("  used aad:       ",myAad,AAD_SIZE);
    printer("  used  iv:       ",header.v1[header.pos].iv,16);
    printer("  myPt      :",pt2,TXT_SIZE);
    printer("  tag1      :",header.v1[header.pos].at,TAG_SIZE);
    printer("  tag2      :",tag2,TAG_SIZE);
    if(memcmp(header.v1[header.pos].at, tag2, TAG_SIZE) == 0){
      printf("\033[0;32m");
      printf("Node %d: valid auth tag\n",node->id);
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("Node %d: invalid auth tag\n",node->id);
      printf("\033[0m");
    }
  }

  header.pos=posPrev;
  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
  return header;
}

/**************************************************************************
 This function handels the processing of the message occuring at Midway
 node W on the messages way from Helper node M back to the source s.

 This function relates to parts of "Algorithm 3" in the paper's appendix.
**************************************************************************/
struct Header iAmWbacktracking(struct Header header, struct Node *node, struct gcm_key_data gkey, uint8_t *freshIv, uint8_t *freshIv2, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  a=__rdtsc();

  struct gcm_context_data gctx;
  uint8_t tag2[TAG_SIZE];
  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */
  memcpy(myAad, header.sid, 16 * sizeof(uint8_t));
  uint8_t cPrev[TXT_SIZE];
  uint8_t posPrev;
  if (header.pos == 0){
    posPrev=(header.pos + VECTOR_LENGTH -1) % VECTOR_LENGTH;
  }
  else{
    posPrev=(header.pos -1) % VECTOR_LENGTH;
  }

  memcpy(cPrev, header.v1[posPrev].ct, TXT_SIZE);
  memcpy(myAad + 16, cPrev, TXT_SIZE * sizeof(uint8_t));

  // and now do the decrpytion
  uint8_t pt2[TXT_SIZE];
  aes_gcm_dec_256(&gkey, &gctx, pt2, header.v1[header.pos].ct, TXT_SIZE, header.v1[header.pos].iv, myAad, AAD_SIZE, tag2, TAG_SIZE);
  if(DEBUG == 1){
    printf("Decryption:\n");
    printer("  used aad:       ",myAad,AAD_SIZE);
    printer("  used  iv:       ",header.v1[header.pos].iv,16);
    printer("  myPt      :",pt2,TXT_SIZE);
    printer("  tag1      :",header.v1[header.pos].at,TAG_SIZE);
    printer("  tag2      :",tag2,TAG_SIZE);
    if(memcmp(header.v1[header.pos].at, tag2, TAG_SIZE) == 0){
      printf("\033[0;32m");
      printf("Node %d: valid auth tag\n",node->id);
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("Node %d: invalid auth tag\n",node->id);
      printf("\033[0m");
    }
  }

  //R.type <- midway
  memset(pt2+8,1,1);

  //nmid <- H.midway
  memcpy(node->nonce,header.midway,8);

  //R.posV2 <- random(0,l-1)
  memset(pt2+10,(rand() % 12),1);

  //R.port2 <- routeTo(d) - bei uns random weil unwichtig
  uint8_t newEgress[4];
  for(int i=0;i<4;i++)
  {
    newEgress[i]=rand() % 256;
  }
  memcpy(pt2+4,newEgress,4);

  //H.V1[H.pos] <- enc(newR,sid||cprev)
  uint8_t tag1[TAG_SIZE];
  aes_gcm_enc_256(&gkey, &gctx, header.v1[header.pos].ct, pt2, TXT_SIZE, freshIv, myAad, AAD_SIZE, tag1, TAG_SIZE);
  memcpy(header.v1[header.pos].iv, freshIv, IV_SIZE);
  memcpy(header.v1[header.pos].at, tag1, TAG_SIZE);

  //H.midway <- Hash(H.dest||nmid||H.V1) (4+8+VECTOR_LENGTH*(16+TXT_SIZE+TAG_SIZE))
  int vLen=4+8+(VECTOR_LENGTH*(16+TXT_SIZE+TAG_SIZE));
  uint8_t vectorToHash[vLen];
  memcpy(vectorToHash,header.dest,4);
  memcpy(vectorToHash+4,header.midway,8);
  memcpy(vectorToHash+12,header.v1,VECTOR_LENGTH*(16+TXT_SIZE+TAG_SIZE));

  uint8_t digest[32];
  getHash(vectorToHash,digest,32);
  memcpy(header.midway,digest,16);

  if(DEBUG == 1){
    printer("digest:  ",digest,16);
  }

  //H.dest <- enc(H.dest,H.sid)
  uint8_t pt3[4];
  memcpy(pt3,header.dest,4);
  aes_gcm_enc_256(&gkey, &gctx, header.dest, pt3, 4, freshIv2, header.sid, 16, tag1, TAG_SIZE);
  memcpy(node->midwayIv, freshIv2, IV_SIZE);
  memcpy(node->midwayAt, tag1, TAG_SIZE);

  //H.status <- "midwayReply"
  header.status=MIDWAY_REPLY;

  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
  header.pos=posPrev;

  return header;
}

/**************************************************************************
 This function handles the processing of the message when returning to the
 source s. These include some checks to detect unexpected manipulation etc.
 It also prepares the session key for communication with the ultimate
 destination that is d.

 This function relates "Algorithm 5" in the paper's appendix.
**************************************************************************/
void backAtS(struct Header *header, struct Header *headerStored, struct Node *node, struct Node *destNode, struct Payload *payload)
{
  // this is a work-around since our entryAS, on the way from s to M, does not check if its predecessor was the client, therefore has NOT R.type=="entryNode" and therefore does not know that there is NO NEED to decrement H.pos on the way back.... i.e. it decrements one too many times, so we increment manually here again
  header->pos=(header->pos + 1) % VECTOR_LENGTH;
  //Assert(H.sid == Hs.sid && H.pos == Hs.pos)
  if(DEBUG ==1){
    if(memcmp(header->sid, headerStored->sid, 16) == 0){
      printf("\033[0;32m");
      printf("S got Midway_Reply with correct SID\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("S got Midway_Reply with incorrect SID\n");
      printf("\033[0m");
    }
    if(memcmp(&header->pos, &headerStored->pos, 1) == 0){
      printf("\033[0;32m");
      printf("S got Midway_Reply with correct H.pos\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("S got Midway_Reply with incorrect H.pos: %d vs %d\n",header->pos,headerStored->pos);
      printf("\033[0m");
    }
  }

  //omiting the pointer comparison here -> see algorithm 5(line 6) for details

  //nrep <- Hash(d||nmid||H.V1)
  int vLen=4+8+(VECTOR_LENGTH*(IV_SIZE+TXT_SIZE+TAG_SIZE));
  uint8_t vectorToHash[vLen];
  memcpy(vectorToHash,node->origDest,4);
  memcpy(vectorToHash+4,node->nonce,8);
  memcpy(vectorToHash+12,header->v1,VECTOR_LENGTH*(IV_SIZE+TXT_SIZE+TAG_SIZE));

  uint8_t nrep[32];
  getHash(vectorToHash,nrep,32);

  //Assert(nrep == H.midway)
  if(DEBUG ==1){
    if(memcmp(header->midway,nrep,16) == 0){
      printf("\033[0;32m");
      printf("S could verify H.midway\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("S could not verify H.midway\n");
      printf("\033[0m");
    }
  }

  //ks−d = ECDH(pubd, privs)
  if(DEBUG ==1){
    printer("old sessionKey:    ",node->sessionKey,32);
  }
  establishSessionKey(node,destNode);
  if(DEBUG ==1){
    printer("new sessionKey:    ",node->sessionKey,32);
  }

  // now go on with line 16 from algo 5
  int ctLen=VECTOR_LENGTH*(IV_SIZE+TXT_SIZE+TAG_SIZE);
  uint8_t newCt[ctLen];
  uint8_t newPt[ctLen];

  vectorToByteArray(header->v1,newPt);
  uint8_t tag1[TAG_SIZE];
  struct gcm_key_data gkey;
  struct gcm_context_data gctx;
  uint8_t *freshIv;
  freshIv = malloc(IV_SIZE);
  generateIv(freshIv);
  aes_gcm_pre_256(node->sessionKey, &gkey);

  aes_gcm_enc_256(&gkey, &gctx, newCt, newPt, ctLen, freshIv, header->sid, 16, tag1, TAG_SIZE);
  memcpy(payload->vectorSafe,newCt,ctLen);
  memcpy(payload->at,tag1,TAG_SIZE);
  memcpy(payload->iv,freshIv,IV_SIZE);
  memcpy(payload->pubKeyS,node->pubKey,32);
  memcpy(headerStored,header, sizeof *header);
  free(freshIv);
}

/**************************************************************************
 This function handles the simple forwarding of the message from s to W.
 There is no need for any writing of routing segments, since all infor-
 mation is already in the heade so that there are only lookups from the
 header.

 This function relates to those parts of "Algorithm 6" in the paper's
 appendix, that only cover forwarding to W and NOT arrival at W.
 It also relates to those parts of "Algorithm 12", the transmission phase,
 that only deal with forwarding, NOT the switch from V1 to V2 conducted by
 Midway node W.
**************************************************************************/
struct Header forwardStoW(struct Header header, struct Node *node, struct gcm_key_data gkey, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  a=__rdtsc();

  struct gcm_context_data gctx;
  uint8_t tag2[TAG_SIZE];
  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */
  memcpy(myAad, header.sid, 16 * sizeof(uint8_t));
  uint8_t cPrev[TXT_SIZE];
  uint8_t posPrev;
  if (header.pos == 0){
    posPrev=(header.pos + VECTOR_LENGTH -1) % VECTOR_LENGTH;
  }
  else{
    posPrev=(header.pos -1) % VECTOR_LENGTH;
  }

  memcpy(cPrev, header.v1[posPrev].ct, TXT_SIZE);
  memcpy(myAad + 16, cPrev, TXT_SIZE * sizeof(uint8_t));

  uint8_t pt2[TXT_SIZE];
  aes_gcm_dec_256(&gkey, &gctx, pt2, header.v1[header.pos].ct, TXT_SIZE, header.v1[header.pos].iv, myAad, AAD_SIZE, tag2, TAG_SIZE);

  if(DEBUG ==1){
    if(memcmp(&header.pos,pt2+9,1) == 0)
    {
      printf("\033[0;32m");
      printf("Node %d: correct posV1 recovered\n",node->id);
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("Node %d: wrong posV1 recovered\n",node->id);
      printf("\033[0m");
    }
  }

  header.pos=(header.pos +1) % VECTOR_LENGTH;
  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);

  return header;
}

/**************************************************************************
 This function handles the operations conducted by Midway node W when for-
 warding to the real destination for the first time. W now has to initi V2
 completely with random data based on a seed (for later checks).

 This function relates to "Algorithm 6" in the paper's appendix.
**************************************************************************/
void iAmWforwardToD(struct Header *header, struct Node *node, uint8_t *freshIv, struct gcm_key_data gkey, uint64_t * c1, uint64_t * c2)
{
  uint64_t a,b;
  a=__rdtsc();
  // decrypt H.dest (Alg6:6)
  struct gcm_context_data gctx;
  uint8_t tag2[TAG_SIZE];
  uint8_t encHdest[4];
  int lenV2=VECTOR_LENGTH*(IV_SIZE+TXT_SIZE+TAG_SIZE);
  int copyLenV2=lenV2;
  uint8_t seedVector[lenV2];
  uint8_t encSeedVector[lenV2];
  int offset=0;

  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */

  uint8_t originalR[TXT_SIZE];
  uint8_t posV1, posV2, posPrevV2, posPrev;
  uint8_t ingres[4], egres[4], pType;
  uint8_t cPrevV2[TXT_SIZE], cPrev[TXT_SIZE];
  uint8_t pMid[17];
  uint8_t* rp = malloc(TXT_SIZE * sizeof(uint8_t));

  // Alg6:2-4
  if (header->pos == 0){
    posPrev=(header->pos + VECTOR_LENGTH -1) % VECTOR_LENGTH;
  }
  else{
    posPrev=(header->pos -1) % VECTOR_LENGTH;
  }

  memcpy(cPrev, header->v1[posPrev].ct, TXT_SIZE);
  memcpy(myAad, header->sid, 16 * sizeof(uint8_t));
  memcpy(myAad + 16, cPrev, TXT_SIZE * sizeof(uint8_t));

  aes_gcm_dec_256(&gkey, &gctx, originalR, header->v1[header->pos].ct, TXT_SIZE, header->v1[header->pos].iv, myAad, AAD_SIZE, tag2, TAG_SIZE);

  // Alg6:6
  memcpy(encHdest,header->dest,4);
  aes_gcm_dec_256(&gkey, &gctx, header->dest, encHdest, 4, node->midwayIv, header->sid, 16, tag2, TAG_SIZE);
  if(DEBUG == 1){
    if(memcmp(tag2, node->midwayAt, 16) == 0){
      printf("\033[0;32m");
      printf("W: H.dest successfully reconstructed\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("W: H.dest incorrectly reconstructed\n");
      printf("\033[0m");
    }
  }

  // Alg 6:8
  while(lenV2>16)
  {
    //printf("offset = %d and remaing vlen = %d\n",offset,lenV2);
    memcpy(seedVector+offset,node->midwaySeed,16);
    lenV2=lenV2-16;
    offset=offset+16;
  }
  // this is for the CPRNG
  //Alg 6:7
  // now encrypt the seed vector
  aes_gcm_enc_256(&gkey, &gctx, encSeedVector, seedVector, copyLenV2, node->midwayIv2, header->sid, 16, tag2, TAG_SIZE);
  // now populate V2 with encrypted seed vector
  offset=0;
  for(int n=0;n<VECTOR_LENGTH;n++)
  {
    memcpy(header->v2[n].ct,encSeedVector+offset,TXT_SIZE);
    offset=offset+TXT_SIZE;
    memcpy(header->v2[n].at,encSeedVector+offset,TAG_SIZE);
    offset=offset+TAG_SIZE;
    memcpy(header->v2[n].iv,encSeedVector+offset,IV_SIZE);
    offset=offset+IV_SIZE;
  }

  // Alg 6:9
  uint8_t distToD=6; /* fixed, counted 4 to 13 while omitting 5,6,7 as the lead to helper*/

  // This is preparation for operating with old and new R
  memcpy(ingres,originalR,4);
  memcpy(egres,originalR+4,4);
  memcpy(&pType,originalR+8,1);
  memcpy(&posV1,originalR+9,1);
  memcpy(&posV2,originalR+10,1);

  // Alg 6:10
  if (posV2 == 0){
    posPrevV2=(posV2 + VECTOR_LENGTH -1);
  }
  else{
    posPrevV2=(posV2 -1);
  }
  memcpy(cPrevV2, header->v2[posPrevV2].ct, TXT_SIZE);

  // Alg 6:11
  //egress must be updated since we are now routing towards the real destination for the first time
  for (int u=0;u<4;u++) {
    egres[u]=rand() % 256;
  }
  //construction of new routing entry R (could be simplified by memcpy(originalR+4,egres,4);)
  memcpy(rp, ingres, 4 * sizeof(uint8_t));
  memcpy(rp + 4, egres, 4 * sizeof(uint8_t));
  memcpy(rp + 8, &pType, sizeof(uint8_t));
  memcpy(rp + 9, &posV1, sizeof(uint8_t));
  memcpy(rp + 10, &posV2, sizeof(uint8_t));
  //printer("WforwardToD: ",rp,TXT_SIZE);
  memcpy(myAad, header->sid, 16 * sizeof(uint8_t));
  memcpy(myAad + 16, cPrevV2, TXT_SIZE * sizeof(uint8_t));
  memcpy(header->v2[posV2].iv,freshIv,IV_SIZE);

  aes_gcm_enc_256(&gkey, &gctx, header->v2[posV2].ct, rp, TXT_SIZE, header->v2[posV2].iv, myAad, AAD_SIZE, header->v2[posV2].at, TAG_SIZE);

  // Alg 6:12-13
  memcpy(myAad + 16, header->v1[posV1].ct, TXT_SIZE * sizeof(uint8_t));
  memcpy(pMid,node->midwaySeed,16);
  memcpy(pMid+16,&distToD,1);
  if(DEBUG == 1){
    printer("WforwardToD: pMid ",pMid,17);
    printer("WforwardToD: stored midway seed ",node->midwaySeed,16);
  }
  aes_gcm_enc_256(&gkey, &gctx, header->midway, pMid, 17, node->midwayIv3, myAad, AAD_SIZE, node->midwayAt, TAG_SIZE);

  // Alg 6:14-15
  header->status=HANDSHAKE_TO_D;
  header->pos= (posV2 + 1) % VECTOR_LENGTH;

  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
  free(rp);
}

/**************************************************************************
 This function handles the forwarding of the message across the nodes from
 W to d. The intermediate routing nodes all write their routing info into
 the header's routing segment's V2.

 This function relates to "Algorithm 7" in the paper's appendix.
**************************************************************************/
struct Header wToD(struct Header header, struct Node node, struct gcm_key_data gkey, uint8_t *freshIv, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  a=__rdtsc();

  struct gcm_context_data gctx;
  uint8_t ingres[4], egres[4], pType, posV1, posV2;
  uint8_t myCt[TXT_SIZE];
  uint8_t* rp = malloc(TXT_SIZE * sizeof(uint8_t)); // array to hold the result
  uint8_t tag1[TAG_SIZE];
  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */
  uint8_t cPrev[TXT_SIZE];
  uint8_t posPrev;

  /*
  Now we prepare the data fields for R, these contain:
    ingres  32 bit randomly chosen (fictive)
    egres   32 bit randomly chosen (fictive)
    type     8 bit randomly chosen (irrelevant at this point)
    posV1 is the pos we have from the header
    posV2 should be a value that is obviously bogus (i.e. beyond the length of V2)
  */

  for (int i=0;i<4;i++) {
    ingres[i]=rand() % 256;
    egres[i]=rand() % 256;
  }

  pType=0;
  posV2=header.pos;
  /* the following will generate a number that is beyond the array size, thus is obvious nonsense that can be detected as such */
  posV1=rand() % 256 + VECTOR_LENGTH;

  if(DEBUG == 1){
    printf("Parameters for R\n\n");
    printer("  ingres:    ", ingres, 4);
    printer("  egres:     ", egres, 4);
    printer("  pType:     ", &pType, 1);
    printer("  posV1:     ", &posV1, 1);
    printer("  posV2:     ", &posV2, 1);
  }

  // now generate routing entry R concatenating ingres, egres, type, posV1 and posV2
  memcpy(rp, ingres, 4 * sizeof(uint8_t));
  memcpy(rp + 4, egres, 4 * sizeof(uint8_t));
  memcpy(rp + 8, &pType, sizeof(uint8_t));
  memcpy(rp + 9, &posV1, sizeof(uint8_t));
  memcpy(rp + 10, &posV2, sizeof(uint8_t));

  if(DEBUG == 1){
    printf("Encryption:\n");
    printer("  generated R:         ", rp, TXT_SIZE);
  }

  // create authentication data
  memcpy(myAad, header.sid, 16);

  if (header.pos == 0){
    posPrev=(header.pos + VECTOR_LENGTH -1);
  }
  else{
    posPrev=(header.pos -1);
  }

  memcpy(cPrev, header.v2[posPrev].ct, TXT_SIZE);
  memcpy(myAad + 16, cPrev, TXT_SIZE);

  aes_gcm_enc_256(&gkey, &gctx, myCt, rp, TXT_SIZE, freshIv, myAad, AAD_SIZE, tag1, TAG_SIZE);

  if(DEBUG == 1){
    printer("  generated myCt      :",myCt,TXT_SIZE);
    printer("  generated tag1      :",tag1,TAG_SIZE);
  }

  // now save that stuff to the header an increase pos
  memcpy(header.v2[header.pos].ct, myCt, TXT_SIZE);
  memcpy(header.v2[header.pos].iv, freshIv, IV_SIZE);
  memcpy(header.v2[header.pos].at, tag1, TAG_SIZE);

  header.pos=(header.pos + 1) % VECTOR_LENGTH;
  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
  free(rp);
  return header;
}

/**************************************************************************
 This function handles operations upon arrival at d. These comprise
 asserting the SID, establishing the session key with s and preparing data
 for checking at s later.

 This function relates to "Algorithm 8" in the paper's appendix.
**************************************************************************/
void iAmD(struct Header *header, struct Node *node, uint8_t *freshIv, struct gcm_key_data gkey, struct Payload *payload, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  a=__rdtsc();
  uint8_t digest[32];
  uint8_t tag2[TAG_SIZE];
  int ctLen=VECTOR_LENGTH*(IV_SIZE+TXT_SIZE+TAG_SIZE);
  struct gcm_context_data gctx;
  uint8_t ptV1[ctLen];
  uint8_t currentV1[2*ctLen];

  // Alg 8:2
  getHash(payload->pubKeyS,digest,32);
  if(DEBUG ==1){
    if(memcmp(header->sid, digest, 16) == 0)
    {
      printf("\033[0;32m");
      printf("D: SID and PubS fit\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("D: SID and PubS do not fit\n");
      printf("\033[0m");
    }
  }

  // Alg 8:3
  curve25519_donna(node->sessionKey, node->privKey, payload->pubKeyS);

  // Alg 8:4
  aes_gcm_pre_256(node->sessionKey, &gkey);
  aes_gcm_dec_256(&gkey, &gctx, ptV1, payload->vectorSafe, ctLen, payload->iv, header->sid, 16, tag2, TAG_SIZE);

  if(DEBUG ==1){
    if(memcmp(payload->at, tag2, 16) == 0)
    {
      printf("\033[0;32m");
      printf("D: Decrypt V1 with correct Tag\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("D: Decrypt V1 with incorrect Tag\n");
      printf("\033[0m");
    }
  }

  // Alg 8:5
  vectorToByteArray(header->v1,currentV1);

  if(DEBUG ==1){
    if(memcmp(currentV1, ptV1, ctLen) == 0)
    {
      printf("\033[0;32m");
      printf("D: Assert V1 OK\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("D: Assert V1 failed\n");
      printf("\033[0m");
    }
  }

  // Alg 8:6
  vectorToByteArray(header->v2,ptV1);
  memcpy(currentV1+ctLen,ptV1,ctLen);
  aes_gcm_enc_256(&gkey, &gctx, payload->vectorSafe, currentV1, 2*ctLen, freshIv, header->sid, 16, payload->at, TAG_SIZE);
  memcpy(payload->iv,freshIv,IV_SIZE);

  // Alg 8:7
  memset(header->dest,0,4);
  header->status=REPLY_TO_W;

  // Alg 8:9 needs deepcopy which we do not have currently. since this is about performance measuring and not attacks, this is not implemented here.
  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
  if (header->pos == 0){
    header->pos=(header->pos + VECTOR_LENGTH -1);
  }
  else{
    header->pos=(header->pos -1);
  }
}

/**************************************************************************
 This function handles the message's forwarding from d to W. In this pro-
 cess, the nodes only have to look up the previously stored routing entries
 from V2.

 This function relates to those parts of "Algorithm 9" in the paper's
 appendix, that handle the forwarding of the message from d to W but NOT
 the operations upon arrivel at W.
**************************************************************************/
struct Header dToW(struct Header header, struct Node *node, struct gcm_key_data gkey, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  a=__rdtsc();

  struct gcm_context_data gctx;

  uint8_t tag2[TAG_SIZE];
  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */
  memcpy(myAad, header.sid, 16 * sizeof(uint8_t));
  uint8_t cPrev[TXT_SIZE];
  uint8_t posPrev;
  if (header.pos == 0){
    posPrev=(header.pos + VECTOR_LENGTH -1) % VECTOR_LENGTH;
  }
  else{
    posPrev=(header.pos -1) % VECTOR_LENGTH;
  }

  memcpy(cPrev, header.v2[posPrev].ct, TXT_SIZE);
  memcpy(myAad + 16, cPrev, TXT_SIZE * sizeof(uint8_t));

  uint8_t pt2[TXT_SIZE];
  aes_gcm_dec_256(&gkey, &gctx, pt2, header.v2[header.pos].ct, TXT_SIZE, header.v2[header.pos].iv, myAad, AAD_SIZE, tag2, TAG_SIZE);

  header.pos=posPrev;
  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
  return header;
}

/**************************************************************************
 This function handles operations performed by W, when the message is
 coming from d for the first time. This includes checking the number of
 changed entries in V2 but also setting the position pointer back to V1
 for the rest of the routing back to s.

 This function relates to the part of "Algorithm 9" in the paper's
 appendix, where arrival at W is covered.
**************************************************************************/
void iAmWbackToS(struct Header *header, struct Node *node, uint8_t *freshIv, struct gcm_key_data gkey, uint64_t * c1, uint64_t * c2)
{
  uint64_t a,b;
  a=__rdtsc();
  struct gcm_context_data gctx;
  uint8_t tag2[TAG_SIZE];
  uint8_t cPrevV2[TXT_SIZE];
  uint8_t originalRV2[TXT_SIZE];
  uint8_t posV1, posV2, posPrevV2, posPrevV1;
  uint8_t myAad[AAD_SIZE];
  uint8_t pMid[17];
  int lenV2=VECTOR_LENGTH*(IV_SIZE+TXT_SIZE+TAG_SIZE);
  int copyLenV2=lenV2;
  uint8_t seedVector[lenV2];
  uint8_t encSeedVector[lenV2];
  uint8_t seed[16];
  uint8_t aadForMAC[2*TXT_SIZE+16];
  int offset=0;
  uint8_t dummyCT[2], dummyPT[2];

  generateIv(node->midwayIv4);

  // Alg 9:2
  posV2=header->pos;
  if (header->pos == 0){
    posPrevV2=(header->pos + VECTOR_LENGTH -1);
  }
  else{
    posPrevV2=(header->pos -1);
  }
  memcpy(cPrevV2, header->v2[posPrevV2].ct, TXT_SIZE);

  // Alg 9:3-4
  memcpy(myAad, header->sid, 16 * sizeof(uint8_t));
  memcpy(myAad + 16, cPrevV2, TXT_SIZE * sizeof(uint8_t));
  aes_gcm_dec_256(&gkey, &gctx, originalRV2, header->v2[header->pos].ct, TXT_SIZE, header->v2[header->pos].iv, myAad, AAD_SIZE, tag2, TAG_SIZE);
  if(DEBUG == 1){
    if(memcmp(originalRV2+10, &posV2, 1) == 0){
      printf("\033[0;32m");
      printf("W: Pos ok\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("W: Pos not ok\n");
      printf("\033[0m");
    }
  }

  // Alg 9:7-8
  memcpy(&posV1,originalRV2+9,1);
  memcpy(myAad + 16, header->v1[posV1].ct, TXT_SIZE * sizeof(uint8_t));
  aes_gcm_dec_256(&gkey, &gctx, pMid, header->midway, 17, node->midwayIv3, myAad, AAD_SIZE, tag2, TAG_SIZE);

  if (posV1 == 0){
    posPrevV1=(posV1 + VECTOR_LENGTH -1);
  }
  else{
    posPrevV1=(posV1 -1);
  }

  // Alg 9:9-17 we omit the check for number of changed entries but generate the the original V2 as if we would
  memcpy(seed,pMid,16);

  while(lenV2>16)
  {
    memcpy(seedVector+offset,seed,16);
    lenV2=lenV2-16;
    offset=offset+16;
  }
  // TODO, hier muss doch noch der rest kopiert werden!?!?!
  aes_gcm_enc_256(&gkey, &gctx, encSeedVector, seedVector, copyLenV2, node->midwayIv2, header->sid, 16, tag2, TAG_SIZE);
  offset=0;
  for(int n=0;n<VECTOR_LENGTH;n++)
  {
    memcpy(seedVector+offset,encSeedVector+offset,TXT_SIZE);
    offset=offset+TXT_SIZE;
    memcpy(seedVector+offset,encSeedVector+offset,TAG_SIZE);
    offset=offset+TAG_SIZE;
    memcpy(seedVector+offset,encSeedVector+offset,IV_SIZE);
    offset=offset+IV_SIZE;
  }

  // Alg 9:18-21
  memcpy(aadForMAC,header->v1[posV1].ct,TXT_SIZE);
  memcpy(aadForMAC+TXT_SIZE,header->v2[header->pos].ct,TXT_SIZE);
  memcpy(aadForMAC+TXT_SIZE+TXT_SIZE,header->sid,16);
  aes_gcm_enc_256(&gkey, &gctx, dummyCT, dummyPT, 0, node->midwayIv4, aadForMAC, 2*TXT_SIZE+16, tag2, TAG_SIZE);
  //printer("MAC: ",tag2,16);
  memcpy(header->midway,tag2,16);

  header->pos=posPrevV1;
  header->status=REPLY_TO_S;

  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);

}

/**************************************************************************
 This function handles the handshake completion that is reached, once the
 first repsonse from d gets back to s.

 This function relates to the part of "Algorithm 11" in the paper's
 appendix, where arrival at W is covered.
**************************************************************************/
void finishAtS(struct Header *header, struct Header *headerStored, struct Node *node, struct Node *destNode, struct Payload *payload, struct gcm_key_data gkey, uint8_t *freshIv, uint64_t * c1, uint64_t * c2)
{
  // this is a work-around since our entryAS, on the way from s to M, does not check if its predecessor was the client, therefore has NOT R.type=="entryNode" and therefore does not know that there is NO NEED to decrement H.pos on the way back.... i.e. it decrements one too many times, so we increment manually here again
  header->pos=(header->pos + 1) % VECTOR_LENGTH;
  uint64_t a, b;
  a=__rdtsc();
  int ctLen=VECTOR_LENGTH*(IV_SIZE+TXT_SIZE+TAG_SIZE);
  uint8_t tag1[TAG_SIZE];
  struct gcm_context_data gctx;
  uint8_t derivedV1[ctLen], derivedV2[ctLen];
  uint8_t bothV[2*ctLen];


  //Alg 11:3
  aes_gcm_dec_256(&gkey, &gctx, bothV, payload->vectorSafe, 2*ctLen, payload->iv, header->sid, 16, tag1, TAG_SIZE);
  if(DEBUG ==1){
    if(memcmp(payload->at, tag1, TAG_SIZE) == 0)
    {
      printf("\033[0;32m");
      printf("S: TAG from V1||V2 ok\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("S: TAG from V1||V2 not ok\n");
      printf("\033[0m");
    }
  }

  // Alg 11:4-5 comparison to stored header is missing here since stored header is incomplete (no deep copy)
  vectorToByteArray(header->v1,derivedV1);
  vectorToByteArray(header->v2,derivedV2);
  if(DEBUG ==1){
    if(memcmp(derivedV1, bothV, ctLen) == 0)
    {
      printf("\033[0;32m");
      printf("S: V1 is correct\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("S: V1 not correct\n");
      printf("\033[0m");
    }

    if(memcmp(derivedV2, bothV+ctLen, ctLen) == 0)
    {
      printf("\033[0;32m");
      printf("S: V2 is correct\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("S: V2 not correct\n");
      printf("\033[0m");
    }
    printer("derived V2:   \n",derivedV2,ctLen);
    printer("retrieved V2: \n",bothV+ctLen,ctLen);
  }

  // Alg 11:6
  header->status=TRANSMISSION_PHASE_TO_D1;

  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
}

/**************************************************************************
 This function handles the switch from V1 to V2 conducted by W in the
 transmission phase. It verfies the MAC from W's encrypted routing info
 in V1 and V2 and switches the pointer to V2.

 This function relates to the part of "Algorithm 12" where Midway node W
 performs the switch from V1 to V2.
**************************************************************************/
void iAmWTransmissionToD2(struct Header *header, struct Node *node, uint8_t *freshIv, struct gcm_key_data gkey, uint64_t * c1, uint64_t * c2)
{
  uint64_t a,b;
  a=__rdtsc();
  struct gcm_context_data gctx;
  uint8_t tag2[TAG_SIZE];
  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */
  memcpy(myAad, header->sid, 16 * sizeof(uint8_t));
  uint8_t cPrevV1[TXT_SIZE];
  uint8_t posPrevV1, posV1, posV2, dummyCT[2], dummyPT[2];
  uint8_t aadForMAC[2*TXT_SIZE+16];
  aes_gcm_pre_256(node->longTermKey, &gkey);
  posV1=header->pos;
  if (header->pos == 0){
    posPrevV1=(header->pos + VECTOR_LENGTH -1) % VECTOR_LENGTH;
  }
  else{
    posPrevV1=(header->pos -1) % VECTOR_LENGTH;
  }

  memcpy(cPrevV1, header->v1[posPrevV1].ct, TXT_SIZE);
  memcpy(myAad + 16, cPrevV1, TXT_SIZE * sizeof(uint8_t));

  uint8_t pt2[TXT_SIZE];
  aes_gcm_dec_256(&gkey, &gctx, pt2, header->v1[header->pos].ct, TXT_SIZE, header->v1[header->pos].iv, myAad, AAD_SIZE, tag2, TAG_SIZE);

  memcpy(&posV2,pt2+10,1);

  if(DEBUG == 1){
    if(memcmp(&header->pos,pt2+9,1) == 0)
    {
      printf("\033[0;32m");
      printf("W: correct posV1 recovered\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("W: incorrect posV1 recovered\n");
      printf("\033[0m");
    }
  }

  // Alg 12:7-10
  memcpy(aadForMAC,header->v1[posV1].ct,TXT_SIZE);
  memcpy(aadForMAC+TXT_SIZE,header->v2[posV2].ct,TXT_SIZE);
  memcpy(aadForMAC+TXT_SIZE+TXT_SIZE,header->sid,16);
  aes_gcm_enc_256(&gkey, &gctx, dummyCT, dummyPT, 0, node->midwayIv4, aadForMAC, 2*TXT_SIZE+16, tag2, TAG_SIZE);

  if(DEBUG == 1){
    if(memcmp(header->midway,tag2,TAG_SIZE) == 0)
    {
      printf("\033[0;32m");
      printf("W: MAC V1||V2 correct\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("W: MAC V1||V2 incorrect\n");
      printf("\033[0m");
    }
  }

  // Alg 12:11-12
  header->status=TRANSMISSION_PHASE_TO_D2;
  header->pos=(posV2+1) % VECTOR_LENGTH;

  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);
}

/**************************************************************************
 This function handles forwarding of the message from W to d. Only lookups
 are needed.

 This function relates to "Algorithm 13" in the paper's appendix.
**************************************************************************/
struct Header forwardWtoD(struct Header header, struct Node *node, struct gcm_key_data gkey, uint64_t * c1, uint64_t * c2)
{
  uint64_t a, b;
  a=__rdtsc();

  struct gcm_context_data gctx;
  uint8_t tag2[TAG_SIZE];
  uint8_t myAad[AAD_SIZE]; /* 128 bit for SID + 128 bit for Cprev */
  memcpy(myAad, header.sid, 16 * sizeof(uint8_t));
  uint8_t cPrev[TXT_SIZE];
  uint8_t posPrev;
  if (header.pos == 0){
    posPrev=(header.pos + VECTOR_LENGTH -1) % VECTOR_LENGTH;
  }
  else{
    posPrev=(header.pos -1) % VECTOR_LENGTH;
  }

  memcpy(cPrev, header.v2[posPrev].ct, TXT_SIZE);
  memcpy(myAad + 16, cPrev, TXT_SIZE * sizeof(uint8_t));

  uint8_t pt2[TXT_SIZE];
  aes_gcm_dec_256(&gkey, &gctx, pt2, header.v2[header.pos].ct, TXT_SIZE, header.v2[header.pos].iv, myAad, AAD_SIZE, tag2, TAG_SIZE);

  if(DEBUG ==1){
    if(memcmp(&header.pos,pt2+10,1) == 0)
    {
      printf("\033[0;32m");
      printf("Node %d: correct posV2 recovered\n",node->id);
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("Node %d: wrong posV2 recovered\n",node->id);
      printf("\033[0m");
    }
  }

  header.pos=(header.pos +1) % VECTOR_LENGTH;
  b=__rdtsc();
  memcpy(c1,&a,8);
  memcpy(c2,&b,8);

  return header;
}

/**************************************************************************
 From a computational perspective, in the transmission phase, effort of
 routing from d to s is the same as that for s to d. Also, the way back has
 already been implemented and measured during handshake. Even though this
 was not the trnasmission phase, operations are the same and are therefore
 not repeated again.
**************************************************************************/

/**************************************************************************
 In the main method, the previously defined functions ar combined to
 iterate through all steps of the protocol.
**************************************************************************/
int main(void)
{
  srand(time(NULL));
  uint64_t c1, c2, rdTest1, rdTest2;

  // declare header struct
  struct Header header;
  struct Header headerStored;
  struct Payload payload;

  memset(&header, 0, sizeof header);
  memset(&payload, 0, sizeof payload);

  // init node keys and helper data
  struct Node nodes[NUM_OF_NODES];
  for (int i=0;i<NUM_OF_NODES;i++) {
    nodes[i]=initializeNode(nodes[i],i);
    initPubPriv(&nodes[i]);

    generateIv(nodes[i].midwayIv);
    generateIv(nodes[i].midwayIv2);
    generateIv(nodes[i].midwayIv3);
    generateIv(nodes[i].midwayIv4);
    rdrand64_step(&rdTest1);
    rdrand64_step(&rdTest2);
    memcpy(nodes[i].midwaySeed,&rdTest1,8);
    memcpy(nodes[i].midwaySeed+8,&rdTest2,8);
  }

  iAmS(&nodes[0],&nodes[7],&nodes[13],&header,&payload,&headerStored);
  if(DEBUG ==1){
    headerprint(&header);
    payloadprint(&payload);
  }

  //do some checks
  //header and headerStored same?
  if(DEBUG ==1){
    if(memcmp(&header,&headerStored,sizeof header)==0)
    {
      printf("\033[0;32m");
      printf("Header copy ok\n");
      printf("\033[0m");
    }
    else
    {
      printf("\033[0;31m");
      printf("Header copy NOT ok\n");
      printf("\033[0m");
    }
  }

  uint8_t *freshIv;
  freshIv = malloc(IV_SIZE);
  uint8_t *freshIv2;
  freshIv2 = malloc(IV_SIZE);
  struct gcm_key_data gkey;

  /*this is the loop for measuring required clock cyles.
  PLEASE NOTE, that the precomputations for the key as
  well as the genration of a fresh IV should not be part
  of the measurement. If a routing node is up and running,
  the required key struct should/would be present already.
  Also we assume that fresh IVs are always at hand since
  these can be generated during idle times. Therefore,
  for this loop to reproduce the measured clock cycles
  from the paper, the call for "generateIv(freshIv);"
  should not be done from within the method "sToM"!

  When placing this loop around other method calls for measurement, make sure to comment out any IV generation within that method and have them generated before start of the loop. Otherwise, your measurements will not only include cycles needed for cryptographic operations but also waiting time. */
  aes_gcm_pre_256(nodes[1].longTermKey, &gkey);
  generateIv(freshIv);
  for(int q=0;q<NUM_OF_SIMS;q++)
  {
    header=sToM(header, nodes[1], gkey, freshIv, &c1, &c2);
    cVector[q]=(int)(c2-c1);
  }

  /* now the message is on its way from s to M and routing nodes create their routing entries within V1. Please note, that in this simple example, there is no real routing information since the route is predetermined. Therefore, fake values are "made up" that are handled like real data to measure real processing timings. */
  aes_gcm_pre_256(nodes[1].longTermKey, &gkey);
  generateIv(freshIv);
  header=sToM(header, nodes[1], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[2].longTermKey, &gkey);
  generateIv(freshIv);
  header=sToM(header, nodes[2], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[3].longTermKey, &gkey);
  generateIv(freshIv);
  header=sToM(header, nodes[3], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[4].longTermKey, &gkey);
  generateIv(freshIv);
  header=sToM(header, nodes[4], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[5].longTermKey, &gkey);
  generateIv(freshIv);
  header=sToM(header, nodes[5], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[6].longTermKey, &gkey);
  generateIv(freshIv);
  header=sToM(header, nodes[6], gkey, freshIv, &c1, &c2);


  /*aes gcm precomputation is not done for node 7 as this node does not need to do any cryptographic operation with its longterm key. Instead, it performd the DH key agreement and then uses the session key to decrypt the payload containg the real destination of the source.*/
  header=iAmHelper(&nodes[7],header,payload, gkey, &c1, &c2);

  //the following instructions generate output on the CLI for tracking, if needed
  if(DEBUG ==1){
    if(memcmp(nodes[0].sessionKey, nodes[7].sessionKey, 32) == 0){
      printf("\033[0;32m");
      printf("S and M derived identical Session Key\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("S and M could not derive identical Session Key\n");
      printf("\033[0m");
    }

    //check if M determines correct d from encrypted payload
    if(memcmp(header.dest, nodes[13].address, 4) == 0){
      printf("\033[0;32m");
      printf("M: correct Destination recovered\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("M: wrong Destination recovered\n");
      printf("\033[0m");
    }

    //check if M determines correct nonce from encrypted payload
    if(memcmp(header.midway, nodes[0].nonce, 8) == 0){
      printf("\033[0;32m");
      printf("M: correct Nonce recovered\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("M: wrong Nonce recovered\n");
      printf("\033[0m");
    }
  }

  // now the backtracking to s starts
  aes_gcm_pre_256(nodes[6].longTermKey, &gkey);
  header=mToS(header, &nodes[6], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[5].longTermKey, &gkey);
  header=mToS(header, &nodes[5], gkey, &c1, &c2);


  // on the way back to s, node 4 determines that it should become the midway node and performs required operations
  aes_gcm_pre_256(nodes[4].longTermKey, &gkey);
  generateIv(freshIv);
  generateIv(freshIv2);
  header=iAmWbacktracking(header, &nodes[4], gkey, freshIv, freshIv2, &c1, &c2);

  // the other nodes continue with backtracking according to the protocol
  aes_gcm_pre_256(nodes[3].longTermKey, &gkey);
  header=mToS(header, &nodes[3], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[2].longTermKey, &gkey);
  header=mToS(header, &nodes[2], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[1].longTermKey, &gkey);
  header=mToS(header, &nodes[1], gkey, &c1, &c2);

  if(DEBUG ==1){
    //check if S and W have identical nonce
    if(memcmp(nodes[4].nonce, nodes[0].nonce, 8) == 0){
      printf("\033[0;32m");
      printf("S and W have identical Nonce\n");
      printf("\033[0m");
    }
    else{
      printf("\033[0;31m");
      printf("S and W do not have identical Nonce\n");
      printf("\033[0m");
    }
  }

  // backtracking phase reaches s which can do checks as described in the paper
  backAtS(&header,&headerStored,&nodes[0],&nodes[13],&payload);

  // now the transmission to real destination d is triggered and the message is on its way from s to the midway node W, where further operations are required.
  aes_gcm_pre_256(nodes[1].longTermKey, &gkey);
  header=forwardStoW(header, &nodes[1], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[2].longTermKey, &gkey);
  header=forwardStoW(header, &nodes[2], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[3].longTermKey, &gkey);
  header=forwardStoW(header, &nodes[3], gkey, &c1, &c2);

  // node 4 detects that it is the midway node W and will initiate communication to s. Among other things, this includes initialization of V2
  aes_gcm_pre_256(nodes[4].longTermKey, &gkey);
  generateIv(freshIv);
  iAmWforwardToD(&header, &nodes[4], freshIv, gkey, &c1, &c2);

  /* now the message is on its way to d and routing nodes create their routing entries. Please note, that in this simple example, there is no real routing information since the route is predetermined. Therefore, fake values are "made up" that are handled like real data */
  aes_gcm_pre_256(nodes[8].longTermKey, &gkey);
  generateIv(freshIv);
  header=wToD(header, nodes[8], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[9].longTermKey, &gkey);
  generateIv(freshIv);
  header=wToD(header, nodes[9], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[10].longTermKey, &gkey);
  generateIv(freshIv);
  header=wToD(header, nodes[10], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[11].longTermKey, &gkey);
  generateIv(freshIv);
  header=wToD(header, nodes[11], gkey, freshIv, &c1, &c2);

  aes_gcm_pre_256(nodes[12].longTermKey, &gkey);
  generateIv(freshIv);
  header=wToD(header, nodes[12], gkey, freshIv, &c1, &c2);

  // the message arrives at d for the first time, where the session key with s is derived
  iAmD(&header, &nodes[13], freshIv, gkey, &payload, &c1, &c2);

  // now the message goes back from d to W
  aes_gcm_pre_256(nodes[12].longTermKey, &gkey);
  header=dToW(header, &nodes[12], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[11].longTermKey, &gkey);
  header=dToW(header, &nodes[11], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[10].longTermKey, &gkey);
  header=dToW(header, &nodes[10], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[9].longTermKey, &gkey);
  header=dToW(header, &nodes[9], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[8].longTermKey, &gkey);
  header=dToW(header, &nodes[8], gkey, &c1, &c2);

  /* W receives the reply from d that is intended to go back to s. But before W does so, it does integrity checks on the header to find out if the routing segment exhibits the expected number of changed entries */
  generateIv(freshIv);
  aes_gcm_pre_256(nodes[4].longTermKey, &gkey);
  iAmWbackToS(&header, &nodes[4], freshIv, gkey, &c1, &c2);

  /* now the mesage goes back from W to s. since this operation is 100% identical to the phase where the message goes from M to s, the same method is reused instead of inserting a duplicate */
  aes_gcm_pre_256(nodes[3].longTermKey, &gkey);
  header=mToS(header, &nodes[3], gkey, &c1, &c2);

  // TODO in every operation that simply forwards (read only), there should be an assert for correct posV
  aes_gcm_pre_256(nodes[2].longTermKey, &gkey);
  header=mToS(header, &nodes[2], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[1].longTermKey, &gkey);
  header=mToS(header, &nodes[1], gkey, &c1, &c2);

  // the reply from d arrives at s, where the integrity of the routing segment is checked
  generateIv(freshIv);
  aes_gcm_pre_256(nodes[0].sessionKey, &gkey);
  finishAtS(&header, &headerStored, &nodes[0], &nodes[13], &payload, gkey, freshIv, &c1, &c2);

  /* now that the session has been established, regular transmission can be adopted. the following operations will only look up routing entries from the segment but not write anymore */
  aes_gcm_pre_256(nodes[1].longTermKey, &gkey);
  header=forwardStoW(header, &nodes[1], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[2].longTermKey, &gkey);
  header=forwardStoW(header, &nodes[2], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[3].longTermKey, &gkey);
  header=forwardStoW(header, &nodes[3], gkey, &c1, &c2);

  /* W notices that it is indeed the midway node and performs the neccessary operations, i.e. looking up the routing entry in V2 etc. */
  aes_gcm_pre_256(nodes[4].longTermKey, &gkey);
  generateIv(freshIv);
  iAmWTransmissionToD2(&header, &nodes[4], freshIv, gkey, &c1, &c2);

  /* from W onwards, the routing nodes behave just like during transmission from s to W with the exception, that they perform their look ups in V2 */
  aes_gcm_pre_256(nodes[8].longTermKey, &gkey);
  header=forwardWtoD(header, &nodes[8], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[9].longTermKey, &gkey);
  header=forwardWtoD(header, &nodes[9], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[10].longTermKey, &gkey);
  header=forwardWtoD(header, &nodes[10], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[11].longTermKey, &gkey);
  header=forwardWtoD(header, &nodes[11], gkey, &c1, &c2);

  aes_gcm_pre_256(nodes[12].longTermKey, &gkey);
  header=forwardWtoD(header, &nodes[12], gkey, &c1, &c2);

  // this call performs operations to determine the average number of cycles for the operation that is enclosed in the for-loop
  cVectorAnalysis();
  free(freshIv);
  free(freshIv2);

  return 0;
}
