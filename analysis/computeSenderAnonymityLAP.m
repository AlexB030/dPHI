% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de


% Compute anonymity set size for LAP. 
%
% The sufix "noLength" indicates that the computation does not require shortest path routing. (Result not part of the PETs paper) 
% The sufix "Single" indicates that only one path is valid for a given source destination part (Result not part of the PETs paper) 


clc
clear all
close all

%load('nographFrom2019withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP')
load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','listIpsPerAS')
load('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        

%% initialize values
numOfNodes=size(listOfNodes,1);
tic
numOfExperiments=1000;
useRandomNodes=0;
useIPrange=1; %If this is set, then we do not count ASes but compute the number of IP addresses belonging to them
chosenM=3; % The VSS parameter. We used 3 in the PETs paper

bidirectional=0; %choose 1 to ignore valley freeness and consider a bidirectional graph

counterSomethingWrong=0;
anonymitySetsizeLAP=zeros(numOfExperiments,5);
anonymitySetsizeLAPSingle=zeros(numOfExperiments,5);
anonymitySetsizeLAPNoLength=zeros(numOfExperiments,5);
anonymitySetsizeLAPNoLengthSingle=zeros(numOfExperiments,5);
anonymitySetsizeVSS=zeros(numOfExperiments,5);
anonymitySetsizeVSSSingle=zeros(numOfExperiments,5);

countNoIP=0; %Just a sanity check variable. There are some ASes that do not have an accociated IP. If they have been chosen as source then we have invalid results. (Yes ugly programming but quick and working)

for(currExperiment=1:numOfExperiments)
    disp(['currExperiment:' num2str(currExperiment)])
    %We generate random path. If entryNode==midwayNode choose new random
    %nodes
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
               %chosen LAP path
                pathStoD=treeToD{source}(1,:);
                % For VSS, each routing element uses 1 to chosenM path
                % (i.e., zero to chosenM-1 dummy routing elements are
                % inserted at each node. The number of routing elements is
                % stored in routingElementSizes
                routingElementSizes=randi(chosenM,size(pathStoD,2),1);
                clear minDistance maxDistance segmentSizes;
                segmentSizes(1)=routingElementSizes(1);
                minDistance(1)=ceil(segmentSizes(1)/chosenM);
                maxDistance(1)=segmentSizes(1);           
                for(i=2:size(routingElementSizes,1))
                    segmentSizes(i)=segmentSizes(i-1)+routingElementSizes(i);
                    minDistance(i)=ceil(segmentSizes(i)/chosenM);
                    maxDistance(i)=segmentSizes(i);           
                end
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
        % For VSS, each routing element uses 1 to chosenM path
        % (i.e., zero to chosenM-1 dummy routing elements are
        % inserted at each node. The number of routing elements is
        % stored in routingElementSizes
        routingElementSizes=randi(chosenM,size(pathStoD,2),1);
        clear minDistance maxDistance segmentSizes;
        segmentSizes(1)=routingElementSizes(1);
        minDistance(1)=ceil(segmentSizes(1)/chosenM);
        maxDistance(1)=segmentSizes(1);           
        for(i=2:size(routingElementSizes,1))
            segmentSizes(i)=segmentSizes(i-1)+routingElementSizes(i);
            minDistance(i)=ceil(segmentSizes(i)/chosenM);
            maxDistance(i)=segmentSizes(i);           
        end
    end
    lengthOfPath=size(pathStoD,2);
  
    %The first node on path S to D knows S as it is the entry node. We now
    %compute the anonymity set size for node 2 up to the destination node.
    for(pointerNode=2:lengthOfPath)
        currNode=pathStoD(pointerNode); %The current node where the attacker is supposed to evasdrop
        prevNode=pathStoD(pointerNode-1); %The previous node from which the message arrived (known from teh ingres field)
        %We count the number of possible IP addresses for different
        %protocls
        counterPossibleLAP=0; %LAP without VSS and shortest path routing where all shortest path are valid
        counterPossibleNoLength=0; %LAP without shortest path routing, i.e., the number of hops does not matter
        counterPossibleLAPSingle=0; % %LAP without VSS and shortest path routing where for every source destination pair the attacker knows exactly which shortest path was chosen (always the first)
        counterPossibleNoLengthSingle=0; %???
        counterPossibleVSS=0; % %LAP with VSS and shortest path routing where all shortest path are valid
        counterPossibleVSSSingle=0; %LAP with VSS and shortest path routing wherewhere for every source destination pair the attacker knows exactly which shortest path was chosen (always the first)
        
        %We now check for every possible source (currSource) if the current node (pointerNode) lies on
        %a shortest path from currSource to D.
        for(currSource=1:size(treeToD,1))
            allPathesforCurrSource=treeToD{currSource}; %the result is an array of all pathes from currSource to D
            
            if(useIPrange==1) %if this flag is set we cound the number of IP addresses. Else we simply count the number of ASes
                numberOfIPsToCount=listIpsPerAS(currSource);
            else
                numberOfIPsToCount=1; %We only count ASes as 1 and ignore the associated number of IP addresses
            end
            %helper variables to ensure that a source is added only once to
            %the list of possible sources
            addedForNoLength=0;
            addedForLAP=0;
            addedForVSS=0;
            addedForLAPSingle=0;
            addedForNoLengthSingle=0;
            addedForVSSSingle=0;
            
            % allPathesforCurrSource is a list of all shortest path from "currSource" to D
            % We know check each of these path and verify if prevNode and currNode are within this path            
            for(currPath=1:size(allPathesforCurrSource,1))
                if(sum(allPathesforCurrSource(currPath,:)==currNode) && sum(allPathesforCurrSource(currPath,:)==prevNode) )
                    %The currNode and prevNode lie within the current path
                    %and hence currSource is a potential valid source. Now
                    %we check for which protocol version (with and without
                    %VSS etc.) it is a valid source
                    
                    if(addedForNoLength==0) %source has not been added
                        %If we do not care about the length, we add this
                        %value
                        %WARNING: WE ONLY LOOK AT SHORTEST PATH, HENCE THIS
                        %IS FAIRLY IRRELEVANT
                        counterPossibleNoLength=counterPossibleNoLength+numberOfIPsToCount;
                        addedForNoLength=1;
                    end
                    if(addedForLAP==0)
                        %for LAP, we know the exact distance to the source.
                        %Hence we check if the detect path has the correct
                        %length.
                        if(distanceToD(currSource)==size(pathStoD,2))
                            counterPossibleLAP=counterPossibleLAP+numberOfIPsToCount;
                            addedForLAP=1;
                        end
                    end
                    
                    
                    if(addedForVSS==0)
                        % For VSS not the exact distance is knows but a
                        % range which depends on the number of routing
                        % elements in the header from the *previous* node
                        distCurrSourceToCurrNode=distanceToD(currSource)-(size(pathStoD,2)-(pointerNode-1)); %the distance between the source and the current node
                        if(distCurrSourceToCurrNode>=minDistance(pointerNode-1) && distCurrSourceToCurrNode<=maxDistance(pointerNode-1)) %The distance to the source node (including the source node) should be within minDistance and maxDistance.
                            counterPossibleVSS=counterPossibleVSS+numberOfIPsToCount;
                        end
                        addedForVSS=1;
                    end
                    %We also compute the anonimity set size for the case
                    %that we assume always the first shortest path is
                    %chosen by the routing algorithm
                    if(currPath==1)

                         if(sum(allPathesforCurrSource(currPath,:)==currNode) && sum(allPathesforCurrSource(currPath,:)==prevNode) )
                            if(addedForNoLengthSingle==0)
                                counterPossibleNoLengthSingle=counterPossibleNoLengthSingle+numberOfIPsToCount;
                                addedForNoLengthSingle=1;
                            end
                            if(addedForLAPSingle==0)
                                if(distanceToD(currSource)==size(pathStoD,2)) %In PHI an attacker can know the distance using the active attacks
                                    counterPossibleLAPSingle=counterPossibleLAPSingle+numberOfIPsToCount;
                                    addedForLAPSingle=1;
                                end
                            end
                            if(addedForVSSSingle==0)
%                                 if(currSource==source) % jsut a debugging 
%                                     disp('tadaaa')
%                                 end
                                distCurrSourceToCurrNode=distanceToD(currSource)-(size(pathStoD,2)-(pointerNode-1)); %the distance between the source and the current node
                                if(distCurrSourceToCurrNode>=minDistance(pointerNode-1) && distCurrSourceToCurrNode<=maxDistance(pointerNode-1)) %The distance to the source node (including the source node) should be within minDistance and maxDistance.
                                    counterPossibleVSSSingle=counterPossibleVSSSingle+numberOfIPsToCount;
                                    addedForVSSSingle=1;
                                end
                            end
                         end
                        
                    end

                end
            end
        end
        anonymitySetsizeLAP(currExperiment,pointerNode-1)=counterPossibleLAP;
        anonymitySetsizeLAPNoLength(currExperiment,pointerNode-1)=counterPossibleNoLength;
        anonymitySetsizeLAPSingle(currExperiment,pointerNode-1)=counterPossibleLAPSingle;
        anonymitySetsizeLAPNoLengthSingle(currExperiment,pointerNode-1)=counterPossibleNoLengthSingle;
        anonymitySetsizeVSS(currExperiment,pointerNode-1)=counterPossibleVSS;
        anonymitySetsizeVSSSingle(currExperiment,pointerNode-1)=counterPossibleVSSSingle;
    end
 end
toc

%anonymitySetsizeVSSM3=anonymitySetsizeVSS;
%anonymitySetsizeVSSSingleM3=anonymitySetsizeVSSSingle;

if(chosenM==2)
    if(useIPrange==1)
        save('sourceAnonymityVSSwithM2forstored1000IP.mat','chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSS','anonymitySetsizeVSSSingle')
    else
        save('sourceAnonymityVSSwithM2forstored1000noIP.mat','chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSS','anonymitySetsizeVSSSingle')
    end
end
if(chosenM==3)
    if(useIPrange==1)
        save('sourceAnonymityVSSwithM3forstored1000IP.mat','chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSSM3','anonymitySetsizeVSSSingleM3')
    else
        save('sourceAnonymityVSSwithM3forstored1000NoIP.mat','chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSSM3','anonymitySetsizeVSSSingleM3')
    end
end
%save('sourceAnonymityVSSwithM2NoBGBforRandom1000IP.mat','chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSS','anonymitySetsizeVSSSingle')
