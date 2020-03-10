% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

% small helper script to find position of the midway node in the PHI path
% and store it in an array for use by the printing function.

clc
clear all
%close all11
numOfExperiments=1000;

%load('nographFrom2019withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP')
load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','destinationListPtoP','listIpsPerAS')
load('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        

numOfNodes=size(listOfNodes,1);
numOfExperiments=1000;

for(currExperiment=1:numOfExperiments)
    source=sourceArray(currExperiment);
    destination=destinationArray(currExperiment);
    helperNode=helperNodeArray(currExperiment);
    %The saved nodes have already been checked to make sure that there
    %is a valid path.
   [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed]=generateShortestValleyfreePHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode);
   midwayNodePosition(currExperiment)=size(pathSM,2)-size(pathWtoM,2);
end

save('midwayNodePosition','midwayNodePosition');