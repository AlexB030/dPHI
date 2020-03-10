% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

%Source anonymity for HORNET
%
% In HORNET, an eavesdropper only learns the previous hop and the next hop.
% It does not know the length nor does it learn the destination (or the
% destination of an intermediate node)
%
% Hence, the source anonymity set size are all nodes where the shortest
% path to the attacker node goes through the previous node.
%Similarly, the destination anonymity are all nodes where there exists a
%shortest path to the destination from the previous node that goes through
%the current and next node.
%

clc
clear all
close all
load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','listIpsPerAS')
load('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        

numOfExperiments=1000;
useRandomNodes=0; %use 1 if you want random nodes, use 1 if you want to use the stored nodes to make experiment repeatable
useIPrange=0; %If this is set, then we do not count ASes but compute the number of IP addresses belonging to them


tic


numOfNodes=size(listOfNodes,1);

counterSomethingWrong=0;
edgetypeArrayAll=zeros(numOfExperiments,5);
anonymitySetsizeHorAll=[];
anonymitySetsizePHIHorAlle=[];

for(currExperiment=1:numOfExperiments)

    edgetypeArray=[];

    disp(['currExperiment:' num2str(currExperiment)])
    toc
    if(useRandomNodes==1)
        hasFailed=1;
        while(hasFailed==1)
            source=randi(numOfNodes);
            destination=randi(numOfNodes);
            if(bidirectional==1)
            [treeToD distanceToD] = shortestAllNoBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,destination);
            else
                [treeToD distanceToD] = shortestAllBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,destination);
            end
           if(distanceToD(source)==inf)
                disp('no source to destination path; choosing new nodes')
           else
               %we chose the first (shortest) path from source to D as the
               %chosen LAP and HORNET path
                pathStoD=treeToD{source}(1,:);
                hasFailed=0;
           end
        end
    else
        source=sourceArray(currExperiment);
        destination=destinationArray(currExperiment);
        if(listIpsPerAS(source)==0)
           disp('Logic error: Source does not have an IP address!!!') 
           countNoIP=countNoIP+1
        end
        [treeToD distanceToD] = shortestAllBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,destination);
        pathStoD=treeToD{source}(1,:);
    end
    

    
    lengthOfPath=size(pathStoD,2);
  
    %The first node on path S to D knows S as it is the entry node. We now
    %compute the anonymity set size for node 2 up to the destination node.
    for(pointerNode=2:lengthOfPath)
        currNode=pathStoD(pointerNode); %The current node where the attacker is supposed to evasdrop
        prevNode=pathStoD(pointerNode-1); %The previous node from which the message arrived (known from teh ingres field)
        %We count the number of possible IP addresses for different
        %protocls
        counterPossibleHorAll=0; %HORNET considering all shortest path
        counterPossibleHorSingle=0; %HORNET only considering the first shortest path
      
        %We now check for every possible source (currSource) if the prevNode lies on the shortest path to currNode (Detstination is unkown).
        [treeToD distanceToCurrNode] = shortestAllBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,currNode);
        
        for(currSource=1:size(treeToD,1))
            allPathesforCurrSource=treeToD{currSource}; %the result is an array of all pathes from currSource to D
            
            if(useIPrange==1) %if this flag is set we cound the number of IP addresses. Else we simply count the number of ASes
                numberOfIPsToCount=listIpsPerAS(currSource);
            else
                numberOfIPsToCount=1; %We only count ASes as 1 and ignore the associated number of IP addresses
            end
            %helper variables to ensure that a source is added only once to
            %the list of possible sources
            addedForHorAll=0;            
            % allPathesforCurrSource is a list of all shortest path from
            % "currSource" to currNode
            % We know check each of these path and verify if prevNode ais within this path            
            for(currPath=1:size(allPathesforCurrSource,1))
                if(sum(allPathesforCurrSource(currPath,:)==prevNode)>0)
                    %The currNode and prevNode lie within the current path
                    %and hence currSource is a potential valid source. 
                    
                    if(addedForHorAll==0) %Has it been added before due to another path in "allPathesforCurrSource"?
                      counterPossibleHorAll=counterPossibleHorAll+numberOfIPsToCount;
                      addedForHorAll=1;
                    end
                    
                    %For single, only the first path is valid
                    if(currPath==1)
                        counterPossibleHorSingle=counterPossibleHorSingle+numberOfIPsToCount;
                    end
                  

                end
            end
        end
        anonymitySetsizeHorAll(currExperiment,pointerNode-1)=counterPossibleHorAll;
        anonymitySetsizeHorSingle(currExperiment,pointerNode-1)=counterPossibleHorSingle;

    end
 end
toc

if(useIPrange==1)
    save('sourceAnonymityHornet1000IP.mat','anonymitySetsizeHorAll','anonymitySetsizeHorSingle')
else
    save('sourceAnonymityHornet1000NoIP.mat','anonymitySetsizeHorAll','anonymitySetsizeHorSingle')
end
