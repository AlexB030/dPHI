function [shortestTree treeDistances] = shortestAllNoBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,destination)

%This function was implemented because I could not find a bug.


nodesToVisitC=[];
nextNodesToVisitC=[];
numOfNodes=size(listOfNodes,1);
treeCtoP=cell(numOfNodes,1);
distancesCtoP=ones(numOfNodes,1)*inf;

%we start at the destination node.
nodesToVisitC(1)=destination;
counterToVisitC=1;
nextCounterToVisitC=0;
counterToVisitP=0;
nextCounterToVisitP=0;

treeCtoP{destination}=[destination];
pathlength=1;
while(counterToVisitC>0 || counterToVisitP>0)
    %We first traverse from the client nodes, then peer-peer nodes than
    %peer and add new nodes that can be reached
    pathlength=pathlength+1;
    for(currNodePointer=1:counterToVisitC)
        currPathes=treeCtoP{nodesToVisitC(currNodePointer)};
        nextPathesArray=ones(size(currPathes,1),size(currPathes,2)+1);
        nextPathesArray(:,2:size(currPathes,2)+1)=currPathes;
        
        %Find all destination to source links for node nodesToVisitC(currNodePointer)
        nodesToCheckC=[sourceCellC{nodesToVisitC(currNodePointer)};sourceCellP{nodesToVisitC(currNodePointer)};sourceCellPtoP{nodesToVisitC(currNodePointer)}];

        %We start by checking all client to peer links and add them if they
        %are shorter or equal to the path length
        for(i=1:size(nodesToCheckC,1))
            if(distancesCtoP(nodesToCheckC(i))==pathlength) %There was already a shortest path to this node. We have to add the current path as well
                entryToAdd=nextPathesArray;
                entryToAdd(:,1)=nodesToCheckC(i);
                treeCtoP{nodesToCheckC(i)}=[treeCtoP{nodesToCheckC(i)};entryToAdd];
            else
                if(distancesCtoP(nodesToCheckC(i))>pathlength) %We found a newest shortest path (happens if it was infinity before, hence we found the first path)
                    % this node was not found in this round yet so we need to add it to the list of nodes to visit in the next round
                        nextCounterToVisitC=nextCounterToVisitC+1;
                        nextNodesToVisitC(nextCounterToVisitC)=nodesToCheckC(i);
                        distancesCtoP(nodesToCheckC(i))=pathlength;
                        treeCtoP{nodesToCheckC(i)}=[];
                        entryToAdd=nextPathesArray;
                        entryToAdd(:,1)=nodesToCheckC(i);
                        treeCtoP{nodesToCheckC(i)}=[treeCtoP{nodesToCheckC(i)};entryToAdd];
                end
            end
        end            
      end

      % we are done for this depth. Now we move to the next depth.
    nodesToVisitC=nextNodesToVisitC;
    counterToVisitC=nextCounterToVisitC;
    nextCounterToVisitC=0;
    nextNodesToVisitC=[];
end
shortestTree=treeCtoP;
treeDistances=distancesCtoP;
end
