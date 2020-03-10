% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

% Script to compute the sender anonymity set size for an attacker located
% between W and d for the PHI and dPHI protocol.
%
% The problem of computing the anonymity set size for W to D is that
% depending on the midway node the path from an attacker A on path P_W-D to
% W and then from W to S is not necessarily one of the shortest path
% between A and S. Whether or not this is the case depends on helper node M
% and the backtracking algorithm. But to compute the anonymity set size for PHI 
% correctly we need to know the distance. Therefore the correct approach would be to
% test for every source S and every helper node M and every destination D
% if the resulting path is a shortest path and if not compute the distance.
% However, this is extremly computationally expensive. 
% 
% We tested for 400 random source, destinations and helper nodes if the
% resulting path is the shortest path. Only in 10 cases was it *not* the
% shortest path.
%
% We therefore chose the conservative approach and included every node in
% the anonymity set size that can be reached with a distance equal or below
% the number of hops: e.g., if the observed distance is 5, so all nodes
% which shortest pathes and distanced 6 or larger are exlcuded, but 
% those of distance 2-5 are valid, not just 5. Node that we actually do not start at the current
% node but the previous node as this node is known (one hop less makes
% quite a difference). Ideally one also verifies that the shortest path
% does not go through the current node.
% This way we actually compute a lower bound of the anonymity set size and
% not the exact anonymity set size


clc
clear all
close all
% load the network architecutre derived from teh 2014 CAIDA data set
load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','listIpsPerAS')
% Load the 1000 pre-computed path so that all figures use the same data
load('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        

numOfExperiments=1000;
useRandomNodes=0; %use 1 if you want random nodes, use 0 if you want to use the stored nodes to make experiment repeatable
useIPrange=1; %If this is set, then we do not count ASes but compute the number of IP addresses belonging to them
useMaxDist=0; %As described above the distance from A_i to s does not need to be the shortest path. If this flag is set to 0, then all path that are longer or equal to the shortest path are valid
% For the PETs paper, the setting was 0. However, in our experiments, a
% not-shortest path path was only 1 hop longer in 2.5 % of cases and only 2
% hobs longer in 1/1000. Setting a 1 or 2 computes the anonymity set
% size by assuming that a path is never more than 1 or 2 hobs longer than
% the shortest path, respectively.


tic


numOfNodes=size(listOfNodes,1);

counterSomethingWrong=0;
anonymityComparisonALL=zeros(numOfExperiments,5);
anonymitySetsizeDPHIAll=zeros(numOfExperiments,5);
anonymitySetsizePHIAll=zeros(numOfExperiments,5);
edgetypeArrayAll=zeros(numOfExperiments,5);

for(currExperiment=1:numOfExperiments)
    anonymitySetsizePHI=[];
    anonymitySetsizePHIActive=[];
    anonymitySetsizeDPHI=[];
    anonymityComparison=[];
    anonymityComparisonActive=[];
    edgetypeArray=[];

    disp(['currExperiment:' num2str(currExperiment)])
    if(useRandomNodes==1)
        %We generate random path. If entryNode==midwayNode choose new random
        %nodes
        hasFailed=1;    
        while(hasFailed==1)
            source=randi(numOfNodes);
            destination=randi(numOfNodes);
            helperNode=randi(numOfNodes);
            [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed]=generateShortestValleyfreePHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode);
        end
    else
        %load precomputed source destination pairs
        source=sourceArray(currExperiment);
        destination=destinationArray(currExperiment);
        helperNode=helperNodeArray(currExperiment);
        %The saved nodes have already been checked to make sure that there
        %is a valid path.
        %now generate a PHI path
       [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed]=generateShortestValleyfreePHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode);
       pathSD=[pathSM(1:find(pathSM==midwayNode)) pathWtoM(1:end)];
       %Verify that there is a valley free path
       [isValleyFree errorCode]=verifyValleyfree(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,pathSD);
       if(isValleyFree==0)
           disp(["not valley free:"+num2str(currExperiment)])
           disp(errorCode)
       end
    end
    

    
    %We start counting at the destination not the midway node as this node
    %is very interesting (attacks likely happen close to the destination or
    %to the source)
    pointer=1;
    for(currNodePointer=size(pathWtoD,2):-1:2) %the first node in pathW-D is W which knows the midway node and has a smaller anonymity setsize. Therefoere we only go back to node w+1
        currNode=pathWtoD(currNodePointer);
        prevNode=pathWtoD(currNodePointer-1); %the node from which the message came
        %with the active attack the attacker can learn the distance
        %S-W-prevNode
        
        %We now check the type of the link from prev to current. If it is a
        %customer to peer or a peer to peer then only customer to peer
        %links are valid for the preceeding path
        phiPathLength=size(pathSM,2)-size(pathWtoM,2)-1+currNodePointer; %Remark: W is in pathSM and pathWtoM and hence minus one

        isCtoP=sum(sourceCellC{prevNode}==currNode);
        isPtoC=sum(sourceCellC{currNode}==prevNode);
        isPtoP=sum(sourceCellPtoP{currNode}==prevNode);
        edgetypeArray(pointer)=isCtoP*1+isPtoC*2+isPtoP*3; %only for later reference if we want to filter it our for plotting
        

        %Compute the corresponding path tree but without the current node
        %as a valid path does not go through the same node twice.
        %Since we want valley-free path, distinguish between PtoC
        if(isPtoC)            
            [treeToNode treeDistancesAll] = shortestAllBGPtreeDestinationIgnoreNodes(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,prevNode,[currNode]);
        else
            [treeToNode treeDistancesAll] = shortestAllBGPtreeCtoPonlyDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,prevNode,[currNode]);
        end
        if(useIPrange==0)
            anonymitySetsizePHI(pointer)=sum(treeDistancesAll<=phiPathLength-1); % Anonymity set size are all nodes that the previous node can reach with a distance of phiPathLength-1 or smaller. Shorter pathes are allowed since routing is not direct but via midway node W which might sometimes result in longer pathes then the shortest path.
            anonymitySetsizeDPHI(pointer)=sum(treeDistancesAll<inf); % All nodes reachable are possible since we do not know the distances. See remarks above why one could slightly reduce it further                          
        else
            if(useMaxDist>0)
                possiblePHIIPs=sum(listIpsPerAS(treeDistancesAll<=phiPathLength-1));
                anonymitySetsizePHI(pointer)=possiblePHIIPs-sum(listIpsPerAS(treeDistancesAll<=phiPathLength-1-useMaxDist)); % Anonymity set size are all nodes that the previous node can reach with a distance of phiPathLength-1 or smaller. Shorter pathes are allowed since routing is not direct but via midway node W which might sometimes result in longer pathes then the shortest path.
                anonymitySetsizeDPHI(pointer)=sum(listIpsPerAS(treeDistancesAll<inf)); % All nodes reachable are possible since we do not know the distances. See remarks above why one could slightly reduce it further              
            else
                anonymitySetsizePHI(pointer)=sum(listIpsPerAS(treeDistancesAll<=phiPathLength-1)); % Anonymity set size are all nodes that the previous node can reach with a distance of phiPathLength-1 or smaller. Shorter pathes are allowed since routing is not direct but via midway node W which might sometimes result in longer pathes then the shortest path.
                anonymitySetsizeDPHI(pointer)=sum(listIpsPerAS(treeDistancesAll<inf)); % All nodes reachable are possible since we do not know the distances. See remarks above why one could slightly reduce it further              
            end
        end
        pointer=pointer+1;

        
    end
    anonymitySetSizePHIAll(currExperiment,1:pointer-1)=anonymitySetsizePHI;
    edgetypeArrayAll(currExperiment,1:pointer-1)=edgetypeArray;

    anonymitySetSizeDPHIAll(currExperiment,1:pointer-1)=anonymitySetsizeDPHI;
    anonymitySetSizeComparisonAll(currExperiment,1:pointer-1)=anonymitySetsizeDPHI/anonymitySetsizePHI;

    toc
end

anonymitySetsizePHIAll=anonymitySetSizePHIAll;
anonymitySetsizeDPHIAll=anonymitySetSizeDPHIAll;
anonymitySetsizeComparisonAll=anonymitySetSizeComparisonAll;
if(useIPrange==1)
    fileEnding='IP.mat';
else
    fileEnding='NoIP.mat';
end
if(useMaxDist)
    fileEnding2='_MaxDist1_';
else
    fileEnding2='';
end
save(['sourceAnonymityWtoDforstored1000' fileEnding2  fileEnding ],'anonymitySetsizePHIAll','anonymitySetsizeDPHIAll','anonymitySetsizeComparisonAll','edgetypeArrayAll');