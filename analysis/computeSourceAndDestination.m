% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

%Script to compute an upper bound on the sender-receiver anonymity


clc
clear all
%close all11
numOfExperiments=1000;

%load('nographFrom2019withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP')
% load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','destinationListPtoP','listIpsPerAS')
% load('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        
% 
% numOfNodes=size(listOfNodes,1);
% numOfExperiments=1000;
% 
% for(currExperiment=1:numOfExperiments)
%     source=sourceArray(currExperiment);
%     destination=destinationArray(currExperiment);
%     helperNode=helperNodeArray(currExperiment);
%     %The saved nodes have already been checked to make sure that there
%     %is a valid path.
%    [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed]=generateShortestValleyfreePHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode);
%    midwayNodePosition(currExperiment)=size(pathSM,2)-size(pathWtoM,2);
% end
% 
% save('midwayNodePosition','midwayNodePosition');

load('midwayNodePosition','midwayNodePosition');
sourceAndDestinationAnonymityDPHI=zeros(1000,15);
sourceAndDestinationAnonymityPHI=zeros(1000,15);


%% insert the source and destination anonymity for nodes on S to M
%starting with source anonymity
load('sourceAnonymityStoMforstored1000IP','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll','anonymityComparisonAll','anonymitySetsizePHIAllSingle','anonymitySetsizeDPHIAllSingle','anonymityComparisonAllSingle');
%source Anonymity from S+1 to D, starting at at s+1
% because it starts at s+1 we store it at the second position


sourceAndDestinationAnonymityDPHI(:,2:9)=anonymitySetsizeDPHIAll(:,1:8);
sourceAndDestinationAnonymityPHI(:,2:9)=anonymitySetsizePHIAll(:,1:8);
%the entry node knows the source, hence the source anonymity is 1
sourceAndDestinationAnonymityDPHI(:,1)=1;
sourceAndDestinationAnonymityPHI(:,1)=1;

%now we multiply the destination anonymity
% destination anonymity S to M. Starting at M-1 (not S)
load('destinationAnonymityStoWforstored1000IP','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll');
for(currExp=1:numOfExperiments)
    % we need to flip the results so that it is from s to M-1 and not M-1
    pointer=1;
    numOfEntries=sum(anonymitySetsizePHIAll(currExp,:)>0);
    while(pointer<4)
        if(anonymitySetsizePHIAll(currExp,pointer)~=0)
            sourceAndDestinationAnonymityDPHI(currExp,numOfEntries+1-pointer)=sourceAndDestinationAnonymityDPHI(currExp,numOfEntries+1-pointer)*anonymitySetsizeDPHIAll(currExp,pointer);
            sourceAndDestinationAnonymityPHI(currExp,numOfEntries+1-pointer)=sourceAndDestinationAnonymityPHI(currExp,numOfEntries+1-pointer)*anonymitySetsizePHIAll(currExp,pointer);
        end
        pointer=pointer+1;
    end
end

%$The nodes on W to M know the destination and hence their destination
%anonymity is 1

%% Now add the source anonymity for node W to d. Note that the destination is known for these notes and hence we only need source anonymity.

%source Anonymity W to D, starting at D (not W)
load('sourceAnonymityWtoDforstored1000IP','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll','anonymitySetsizeComparisonAll','edgetypeArrayAll');
for(currExp=1:numOfExperiments)
    pointer=1;
    numOfEntries=sum(sourceAndDestinationAnonymityDPHI(currExp,:)>0);
        while(pointer<6)
            if(anonymitySetsizePHIAll(currExp,pointer)~=0)
                sourceAndDestinationAnonymityDPHI(currExp,numOfEntries+pointer)=sourceAndDestinationAnonymityDPHI(currExp,numOfEntries+pointer)*anonymitySetsizeDPHIAll(currExp,pointer);
                sourceAndDestinationAnonymityPHI(currExp,numOfEntries+pointer)=sourceAndDestinationAnonymityPHI(currExp,numOfEntries+pointer)*anonymitySetsizePHIAll(currExp,pointer);
            end
        pointer=pointer+1;
    end
end

sourceAndDestinationAnonymityHor=zeros(1000,10);
%% now compute the source destination anonymity for HORNET
load('sourceAnonymityHornet1000IP.mat','anonymitySetsizeHorAll','anonymitySetsizeHorSingle')
sourceAndDestinationAnonymityHor(:,2:8)=anonymitySetsizeHorAll; %source anonymity is computed for the second node as the first knows teh source
sourceAndDestinationAnonymityHor(:,1)=1;

%load destination anonymity, it starts at s and goes to d-1, as the last
%one knows the destination.
load('destinationeAnonymityHornet1000IP.mat','anonymitySetsizeHorAll','anonymitySetsizeHorSingle')

for(currExp=1:numOfExperiments)
    pointer=1;
    numOfEntries=sum(anonymitySetsizeHorAll(currExp,:)>0);
    while(pointer<=numOfEntries)
        sourceAndDestinationAnonymityHor(currExp,pointer)=sourceAndDestinationAnonymityHor(currExp,pointer)*anonymitySetsizeHorAll(currExp,pointer);
        pointer=pointer+1;
    end
end



% done
save('sourceDestinationAnonymityIP','sourceAndDestinationAnonymityDPHI','sourceAndDestinationAnonymityPHI','sourceAndDestinationAnonymityHor')
