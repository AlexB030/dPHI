% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

% Source anonymity from S to M with a routing policy not based on shortest
% path
clc
clear all
close all
load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','listIpsPerAS')
load('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        

numOfExperiments=1000;
useRandomNodes=0; %use 1 if you want random nodes, use 1 if you want to use the stored nodes to make experiment repeatable
useIPrange=1; %If this is set, then we do not count ASes but compute the number of IP addresses belonging to them
useMaxDist=0; %In practice the distance from A_i to s can be shortest distance +1 (2.5% or distance +2 (1/1000). So we test what happens if the only consider distance +1


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
        source=sourceArray(currExperiment);
        destination=destinationArray(currExperiment);
        helperNode=helperNodeArray(currExperiment);
        %The saved nodes have already been checked to make sure that there
        %is a valid path.
       [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed]=generateShortestValleyfreePHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode);
       pathSD=[pathSM(1:find(pathSM==midwayNode)) pathWtoM(1:end)];
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
    for(currNodePointer=size(pathSM,2):-1:2) %the first node in pathW-D is W which knows the midway node and has a smaller anonymity setsize. Therefoere we only go back to node w+1
        currNode=pathSM(currNodePointer);
        prevNode=pathSM(currNodePointer-1); %the node from which the message came
        %with the active attack the attacker can learn the distance
        %S-W-prevNode
        
        %We now check the type of the link from prev to current. If it is a
        %customer to peer or a peer to peer then only customer to peer
        %links are valid for the preceeding path
        phiPathLength=currNodePointer; %Remark: W is in pathSM and pathWtoM and hence minus one

        isCtoP=sum(sourceCellC{prevNode}==currNode);
        isPtoC=sum(sourceCellC{currNode}==prevNode);
        isPtoP=sum(sourceCellPtoP{currNode}==prevNode);
        edgetypeArray(pointer)=isCtoP*1+isPtoC*2+isPtoP*3; %only for later reference if we want to filter it our for plotting
        

        %Compute the corresponding path tree but without the current node
        %as a valid path does not go through the same node twice.
        %Since we want valley-free path, distinguish between PtoC
        if(isPtoC)            
            [treeToNode treeDistancesAll] = shortestAllBGPtreeDestinationIgnoreNodes(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,prevNode,[currNode]);
            %The current node is of course also a valid source with
            %path length zero.
            treeDistancesAll(currNode)=0;
        else
            [treeToNode treeDistancesAll] = shortestAllBGPtreeCtoPonlyDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,prevNode,[currNode]);
            %The current node is of course also a valid source with
            %path length zero.
            treeDistancesAll(currNode)=0;
        end
        if(useIPrange==0)
            anonymitySetsizePHI(pointer)=sum(treeDistancesAll<=phiPathLength-1); % Anonymity set size are all nodes that the previous node can reach with a distance of phiPathLength-1 or smaller. Shorter pathes are allowed since routing is not direct but via midway node W which might sometimes result in longer pathes then the shortest path.
            anonymitySetsizeDPHI(pointer)=sum(treeDistancesAll<inf); % All nodes reachable are possible since we do not know the distances. See remarks above why one could slightly reduce it further                          
        else
            anonymitySetsizePHI(pointer)=sum(listIpsPerAS(treeDistancesAll<=phiPathLength-1)); % Anonymity set size are all nodes that the previous node can reach with a distance of phiPathLength-1 or smaller. Shorter pathes are allowed since routing is not direct but via midway node W which might sometimes result in longer pathes then the shortest path.
            anonymitySetsizeDPHI(pointer)=sum(listIpsPerAS(treeDistancesAll<inf)); % All nodes reachable are possible since we do not know the distances. See remarks above why one could slightly reduce it further              
        end
        pointer=pointer+1;

        
    end
    anonymitySetsizePHIAll(currExperiment,1:pointer-1)=anonymitySetsizePHI;
    edgetypeArrayAll(currExperiment,1:pointer-1)=edgetypeArray;

    anonymitySetsizeDPHIAll(currExperiment,1:pointer-1)=anonymitySetsizeDPHI;

    toc
end


if(useIPrange==1)
    fileEnding='IP.mat';
else
    fileEnding='NoIP.mat';
end

save(['sourceAnonymityNoShortestPathStoMforstored1000'  fileEnding ],'anonymitySetsizePHIAll','anonymitySetsizeDPHIAll','edgetypeArrayAll');