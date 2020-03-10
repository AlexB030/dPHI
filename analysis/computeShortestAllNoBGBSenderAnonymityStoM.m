% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

% COmpute the source anonymity from s to m without considering valley
% freeness but assuming a shortest path routing algorithm

clc
clear all
close all

load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','destinationListPtoP','listIpsPerAS')
load('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        


numOfNodes=size(listOfNodes,1);
tic
numOfExperiments=1000;
useRandomNodes=1;

%If startAtSecondNode==1 we start the analysis at the second node,
%irrespectively if it is midway node or not. Otherwise we start at the
%midway node
startAtSecondNode=1;

useIPrange=1; %If this is set, then we do not count ASes but compute the number of IP addresses belonging to them

%% Main idea: Choose a random setup connection. We then want to find out the anonymity set size of this setup that is eavesdropped between M-W,W, S-W.
%To compute anonymity setzise for a node A in P_s-W and an observed path
%A-1,A for destination M we do the following:
% Option1: destination unkown: Find all s that are in the shortest path tree with destination M. That is
% the anonymity set size of dPHI. Then sort out all elements in the
% shortest path tree that have the wrong distance, this is the anonymity
% set size for PHI with the distance attack.
%
%Option 2: destination known: We would have to find out for the given
%destination and helpe node if backtracking would have been done this far
%and remove those where backtracking would have gone further.
%


tic

%%


counterSomethingWrong=0; % Just for debugging

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
            [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed]=generateShortestNoBGBPHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode);
        end
    else
        source=sourceArray(currExperiment);
        destination=destinationArray(currExperiment);
        helperNode=helperNodeArray(currExperiment);
        %The saved nodes have already been checked to make sure that there
        %is a valid path.
        [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed]=generateShortestNoBGBPHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode);
    end
    
    %% now we compute the source anonymity set size for nodes pathStoM
    % For this we compute all shortest path to the midway node:
    anonymitySetsizePHI=[];
    anonymitySetsizeDPHI=[];
    anonymityComparison=[];
    
    anonymitySetsizePHISingle=[];
    anonymitySetsizeDPHISingle=[];
    anonymityComparisonSingle=[];
    
    %[treeToM,distanceToD] = shortestpathtree(G,'all',helperNode,'OutputForm','cell');
    %Compute all shortest path to helper node M:
    [treeToM distanceToM] = shortestAllNoBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,helperNode);
    [notNeeded arrayWposition(currExperiment)]=max(pathSM==midwayNode); %for later reference if we want to know where the midway nodw was

    
    if(startAtSecondNode==0)
        %we start at midway node W, i.e. we compute anonymity set size from
        %W to M
          lengthOfPath=size(pathWtoM,2)+1;
          [notNeeded starrtingNode]=max(pathSM==midwayNode);       
    else
        %we start at the node after the entry node, i.e. we compute the
        %anonymity set size for s to M
         lengthOfPath=size(pathSM,2)-1;
        starrtingNode=2; %we ver
    end
   
    for(pointerNode=1:lengthOfPath)
        currNode=pathSM(starrtingNode+pointerNode-1); %The current node where the attacker is supposed to evasdrop
        prevNode=pathSM(starrtingNode+pointerNode-2); %The previous node on the path whose address the attacker knows
        counterPossiblePHI=0;
        counterPossibleDPHI=0;
        counterPossiblePHISingle=0;
        counterPossibleDPHISingle=0;
        %We now check for every possible source if the current node can be
        %a shortest path to M
        for(currSource=1:size(treeToM,1))
            allPathesforCurrSource=treeToM{currSource}; %the result is an array of all pathes from currSource to M
            if(useIPrange==1) %if this flag is set we cound the number of IP addresses. Else we simply count the number of ASes
                numberOfIPsToCount=listIpsPerAS(currSource);
            else
                numberOfIPsToCount=1; %We only count ASes as 1 and ignore the associated number of IP addresses
            end
            %helper variables to ensure that a source is added only once to
            %the list of possible sources.
            addedForPHI=0;
            addedForDPHI=0;
            
            for(currPath=1:size(allPathesforCurrSource,1))
                %this is the shortest route using the single shortest route
                %algorithm. I.e., if the attacker knows the shortest path
                %taken
                if(sum(allPathesforCurrSource(currPath,:)==currNode) && sum(allPathesforCurrSource(currPath,:)==prevNode) )
                    %Warning: There can be multiple path to the same
                    %source, hence we have to check if thissource has been
                    %found before.
                    
                    if(addedForDPHI==0)
                        counterPossibleDPHI=counterPossibleDPHI+numberOfIPsToCount;
                        addedForDPHI=1;
                    end
                    if(addedForPHI==0)
                        if(distanceToM(currSource)==size(pathSM,2)) %In PHI an attacker can know the distance using the active attacks
                            counterPossiblePHI=counterPossiblePHI+numberOfIPsToCount;
                            addedForPHI=1;
                        end
                    end
                    %We also compute the anonimity set size for the case
                    %that we assume always the first shortest path is
                    %chosen by the routing algorithm (remark: in this case
                    %a source can only be added once anyways and we do not
                    %need an additional check
                    if(currPath==1)
                         if(sum(allPathesforCurrSource(currPath,:)==currNode) && sum(allPathesforCurrSource(currPath,:)==prevNode) )
                            counterPossibleDPHISingle=counterPossibleDPHISingle+numberOfIPsToCount;
                            if(distanceToM(currSource)==size(pathSM,2)) %In PHI an attacker can know the distance using the active attacks
                                counterPossiblePHISingle=counterPossiblePHISingle+numberOfIPsToCount;
                            end
                        end                       
                    end
                    % We have found that the currNode is part of the
                    % anonimity set size. We can stop looking for this node
                    sourceNotFoundYet=0;
                    break;
                end
            end
        end
        if(counterPossibleDPHI==0)
            disp('shit something is wrong')
            counterSomethingWrong=counterSomethingWrong+1;
        end
        anonymitySetsizePHI(pointerNode)=counterPossiblePHI;
        anonymitySetsizeDPHI(pointerNode)=counterPossibleDPHI;
        anonymityComparison(pointerNode)=(counterPossiblePHI/counterPossibleDPHI)*100;
        anonymitySetsizePHISingle(pointerNode)=counterPossiblePHISingle;
        anonymitySetsizeDPHISingle(pointerNode)=counterPossibleDPHISingle;
        anonymityComparisonSingle(pointerNode)=(counterPossiblePHISingle/counterPossibleDPHISingle)*100;
    end
    anonymitySetsizePHIAll(currExperiment,1:size(anonymitySetsizePHI,2))=anonymitySetsizePHI(1:size(anonymitySetsizePHI,2));
    anonymitySetsizeDPHIAll(currExperiment,1:size(anonymitySetsizePHI,2))=anonymitySetsizeDPHI(1:size(anonymitySetsizePHI,2));
    anonymityComparisonAll(currExperiment,1:size(anonymitySetsizePHI,2))=anonymityComparison(1:size(anonymitySetsizePHI,2));
    
    anonymitySetsizePHIAllSingle(currExperiment,1:size(anonymitySetsizePHI,2))=anonymitySetsizePHISingle(1:size(anonymitySetsizePHI,2));
    anonymitySetsizeDPHIAllSingle(currExperiment,1:size(anonymitySetsizePHI,2))=anonymitySetsizeDPHISingle(1:size(anonymitySetsizePHI,2));
    anonymityComparisonAllSingle(currExperiment,1:size(anonymitySetsizePHI,2))=anonymityComparisonSingle(1:size(anonymitySetsizePHI,2));
end
toc
if(useIPrange==1)

     save('sourceAnonymityStoMNoBGBforRandom1000NoIP','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll','anonymityComparisonAll','anonymitySetsizePHIAllSingle','anonymitySetsizeDPHIAllSingle','anonymityComparisonAllSingle');
else
     save('sourceAnonymityStoMNoBGBforRandom1000NoIP','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll','anonymityComparisonAll','anonymitySetsizePHIAllSingle','anonymitySetsizeDPHIAllSingle','anonymityComparisonAllSingle');
end
     