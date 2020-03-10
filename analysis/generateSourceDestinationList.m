% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

%Helper script to randomly generate 1000 (or more if you want) source
%destinations pairs and stores and PHI paths and stores it in a file so
%that you can run multiple experiments using the same nodes.


clc
clear all

numOfExperiments=10000;

load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','listIpsPerAS')
numOfNodes=size(listOfNodes,1);
for(i=1:numOfExperiments)
    hasFailed=1;    
    while(hasFailed==1)
        source=randi(numOfNodes);
        destination=randi(numOfNodes);
        helperNode=randi(numOfNodes);
        %verify that a valley-free PHI path via the helper node is
        %possible.
        [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed]=generateShortestValleyfreePHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode);
        % We also need to check if there is a path between source and
        % destination for the LAP protocol (it can happen that there is a
        % valley-free path via the helper node, but not a direct valley
        % free path.
        [treeToD distanceToD] = shortestAllBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,destination);
        if(size(treeToD{source},1)==0)
           hasFailed=1;
           disp('error: no path from source to destination for LAP')  
        end
        if(listIpsPerAS(source)==0)
           hasFailed=1;
           disp('error: Source does not have an IP address!') 
        end
        if(listIpsPerAS(destination)==0)
           hasFailed=1;
           disp('error: Destination does not have an IP address!') 
        end
    end 
    sourceArray(i)=source;
    destinationArray(i)=destination;
    helperNodeArray(i)=helperNode;
    disp(['curr i:' num2str(i)])
end
    
    
%save('savedSourceDestinationHelperNodes2014','sourceArray','destinationArray','helperNodeArray')        
