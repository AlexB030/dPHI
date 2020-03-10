% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

% Script to compute the destination anonymity for PHI and dPHI


clc
clear all
%close all

%load('nographFrom2019withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP')
load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','destinationListPtoP','listIpsPerAS')
load('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        

numOfNodes=size(listOfNodes,1);
tic
numOfExperiments=1000;
useRandomNodes=0;

useIPrange=0; %If this is set, then we do not count ASes but compute the number of IP addresses belonging to them

tic


anonymityComparisonALL=zeros(numOfExperiments,2);
anonymitySetsizeDPHIAll=zeros(numOfExperiments,2);
anonymitySetsizePHIAll=zeros(numOfExperiments,2);

anonymityComparisonALLSingle=zeros(numOfExperiments,2);
anonymitySetsizeDPHIAllSingle=zeros(numOfExperiments,2);
anonymitySetsizePHIAllSingle=zeros(numOfExperiments,2);
numOfNodes=size(listOfNodes,1);

for(currExperiment=1:numOfExperiments)
    disp(['currExperiment:' num2str(currExperiment)])
    %We generate random path. If entryNode==midwayNode choose new random
    %nodes

    if(useRandomNodes==1)
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
    end
    lengthOfWtoD=size(pathWtoD,2);
    %% now we compute the source anonymity set size for nodes pathStoM
    % For this we compute all shortest path to the midway node:
    anonymitySetsizePHI=[];
    anonymitySetsizeDPHI=[];
    anonymityComparison=[];
    
    anonymitySetsizePHISingle=[];
    anonymitySetsizeDPHISingle=[];
    anonymityComparisonSingle=[];
    
    % We start at position W-1: This node knows the helper node. It also
    % knows the destination lies such that the destination is such that the
    % midway node is chosen on path P_A_M. We therefore compute all
    % destinations for which this is the case.
    
    pointer=1;
    [treeToM treeDistancesToM]=shortestAllBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,helperNode); %Remark, it does not matter if it is destination or source tree - valley freenes is symetric
    for(attackerPathPosition=1:(find(pathSM==midwayNode)-1));
        anonymitySetsizeDPHI(pointer)=0;
        anonymitySetsizePHI(pointer)=0;
       % If the assume a shortest path routing but not that the attacker
       % knows which shortest path was used we do not know exactly know teh
       % nodes in the path to M. We therefore have to check all possible
       % path to M :(
       attackerNode=pathSM(attackerPathPosition);
       possiblePath=treeToM{attackerNode};
       undecidedDestinationsDPHI=1:numOfNodes; %all destinations that are still undecided if they are possible or not
       undecidedDestinationsPHI=1:numOfNodes; %all destinations that are still undecided if they are possible or not
       for(currPathPointer=1:size(possiblePath,1))
           currPath=possiblePath(currPathPointer,:);

           %we now check for every possible midway position which destinations
           %are possible (i.e. destinations for which backtracking stops before
           %the attacker node is reached)
           for(currMidwayPosition=size(currPath,2):-1:2) 
                currMidwayNode=currPath(currMidwayPosition);
                [treeFromPrev treeDistancesFromPrev]=shortestAllBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,currPath(currMidwayPosition-1)); 
                %if the currMidwayNode is not in in of the path treeFromPrev then for this
                %destination the current node would become midway node and hence it
                %is a valid destination.
                destinationsNotToRemoveDPHI=ones(size(undecidedDestinationsDPHI));
                destinationsNotToRemovePHI=ones(size(undecidedDestinationsPHI));
                
                % Check DPHI, in this case distances do not matter
                for(currDestPointer=1:size(undecidedDestinationsDPHI,2))
                    pathesToDest=treeFromPrev{undecidedDestinationsDPHI(currDestPointer)};
                    if(sum(sum(pathesToDest==currMidwayNode))>0) %in one of the pathes the current node is in the shortest path. Hence, the current node could have been chosen as midway node for the tested destination.
                        if(useIPrange==1)
                            anonymitySetsizeDPHI(pointer)=anonymitySetsizeDPHI(pointer)+listIpsPerAS(undecidedDestinationsDPHI(currDestPointer));
                        else
                            anonymitySetsizeDPHI(pointer)=anonymitySetsizeDPHI(pointer)+1;
                        end
                        destinationsNotToRemoveDPHI(currDestPointer)=0;
                    end
                end
                %now we remove the found destinations from the list 
                undecidedDestinationsDPHI=undecidedDestinationsDPHI(destinationsNotToRemoveDPHI>0);
                
                % Now check PHI, in this case the distance needs to match
                for(currDestPointer=1:size(undecidedDestinationsPHI,2))
                    if(treeDistancesFromPrev(currDestPointer)==lengthOfWtoD+2)
                        pathesToDest=treeFromPrev{undecidedDestinationsPHI(currDestPointer)};
                        if(sum(sum(pathesToDest==currMidwayNode))>0) %in one of the pathes the current node is in the shortest path. Hence, the current node could have been chosen as midway node for the tested destination.
                            if(useIPrange==1)
                                anonymitySetsizePHI(pointer)=anonymitySetsizePHI(pointer)+listIpsPerAS(undecidedDestinationsPHI(currDestPointer));
                            else
                                anonymitySetsizePHI(pointer)=anonymitySetsizePHI(pointer)+1;
                            end
                            destinationsNotToRemovePHI(currDestPointer)=0;
                        end
                    end
                end
                %now we remove the found destinations from the list 
                undecidedDestinationsPHI=undecidedDestinationsPHI(destinationsNotToRemovePHI>0);
           end
       end
        
       pointer=pointer+1;
   end
   anonymitySetsizeDPHIAll(currExperiment,1:pointer-1)=anonymitySetsizeDPHI;
   anonymitySetsizePHIAll(currExperiment,1:pointer-1)=anonymitySetsizePHI;
    toc
end

if(useIPrange==1)
    save('destinationAnonymityStoWforstored1000IP','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll');
else
    save('destinationAnonymityStoWforstored1000NoIP','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll');
end