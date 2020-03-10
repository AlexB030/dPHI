% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

function plotCDFComparison(resultList,numOfResults,experimentNames,titleFirst,titleSecond,isIP,saveFigures,fileName,plotIgnoreDistance,plotPerDistance)

%%
%resultList={anonymitySetsizeDPHIAll,anonymitySetsizeLAP};
%numOfResults=2;
%isIP=1;
%experimentNames={"DPHI","LAP"};
plotOneSetAllDistances=0;
plotAllDistances=0;
plotComparePerDistance=plotPerDistance;
plotDifferencePerDistance=0;
%markerIndces={'r--h','r-h','b--*','b-*','g--s','g-s','k-^','k->','r-<','g-p','b-+'};
markerIndces={'r-h','g-o','b-*','c-v','m-s','k-d','k-^','k->','r-<','g-p','b-+'};
ylimValue=[0 1];
yticksValues=[0:0.2:1];
theLineWidth=1.5;
theMarkerWidth=5;

%%

clear logxAxis;
if(isIP==1)
    for(i=1:33)
        logxAxis(i)=2^(i-1);
    end
    if(1)
        xlimValue=[7 33];
    else
        xlimValue=[1 33];
    end
    xticksValues=[1:2:33];
    xtickString={'1^0','2^2','2^4','2^6','2^8','2^{10}','2^{12}','2^{14}','2^{16}','2^{18}','2^{20}','2^{22}','2^{24}','2^{26}','2^{28}','2^{30}','2^{32}'};
end
if(isIP==0)
    for(i=1:17)
        logxAxis(i)=2^(i-1);
    end
    xlimValue=[1 17];
    xticksValues=[1:1:17];
    xtickString={'1','2','2^2','2^3','2^4','2^5','2^6','2^7','2^8','2^9','2^{10}','2^{11}','2^{12}','2^{13}','2^{14}','2^{15}','2^{16}'};
end
if(isIP==4)
    for(i=1:65)
        logxAxis(i)=2^(i-1);
    end
    xlimValue=[7 65];
    xticksValues=[1:4:65];
    xtickString={'1^0','2^4','2^8','2^{12}','2^{16}','2^{20}','2^{24}','2^{28}','2^{32}','2^{36}','2^{40}','2^{44}','2^{48}','2^{52}','2^{56}','2^{60}','2^{64}'};
end


%% We now plot the CDF of one result for all distances
%compute the cdf
if(plotOneSetAllDistances==1)
    for(currResult=1:numOfResults)
        clear cdfSetSize legendName;
        setSizeToPlot=resultList{currResult};
        figure;
        hold all;
        for(currDistance=1:size(setSizeToPlot,2))
            clear cdfSetSize
            validEntries=setSizeToPlot(setSizeToPlot(:,currDistance)>0,currDistance);
            numOfEntries=size(validEntries,1);
            if(numOfEntries>0)
                for(i=1:size(logxAxis,2))
                    cdfSetSize(i)= sum(validEntries<=logxAxis(i))/numOfEntries;
                end
                legendName{currDistance}=num2str(currDistance)+"("+num2str(numOfEntries)+")";
                plot(cdfSetSize,markerIndces{currDistance}, 'LineWidth',theLineWidth,'MarkerSize',theMarkerWidth) 
            end

        end


        xlim(xlimValue)
        xticks(xticksValues)
        xticklabels(xtickString)
                ylim(ylimValue)
        yticks(yticksValues)
        legend(legendName);
        legend('Location','best')   
        xlabel('anonymity set-size')
        ylabel('probability')
        title({titleFirst+experimentNames{currResult};titleSecond});
        ax=gca;
        ax.FontSize=14;
    end
end


distanceBound=inf;
for(currResult=1:numOfResults)
    if(size(resultList{currResult},2)<distanceBound)
        distanceBound=size(resultList{currResult},2);
    end
end
 
 %% Now we plot same distance but different results
if(plotComparePerDistance==1)
    for(currDistance=1:distanceBound)
        figure;
        hold all;
        clear legendName;
        for(currResult=1:numOfResults)
            clear cdfSetSize;
            setSizeToPlot=resultList{currResult};
            validEntries=setSizeToPlot(setSizeToPlot(:,currDistance)>0,currDistance);
            numOfEntries=size(validEntries,1);
            if(numOfEntries>0)
                for(i=1:size(logxAxis,2))
                    cdfSetSize(i)= sum(validEntries<=logxAxis(i))/numOfEntries;
                end
                legendName{currResult}=experimentNames{currResult}+"("+num2str(numOfEntries)+")";
                plot(cdfSetSize,markerIndces{currResult}, 'LineWidth',theLineWidth,'MarkerSize',theMarkerWidth) 
            end
        end
        xlim(xlimValue)
        xticks(xticksValues)
        ylim(ylimValue)
        yticks(yticksValues)
        xticklabels(xtickString)
        legend(legendName);
        legend('Location','best')   
        xlabel('anonymity set-size')
        ylabel('probability')
        title({titleFirst; titleSecond+num2str(currDistance)});
        ax=gca;
        ax.FontSize=14;
        if(saveFigures==1)
            print(fileName+"PerDistance"+num2str(currDistance) ,'-dpng')
        end
    end
end

%% now we ignore the position and only plot a single line, i.e. irrespecively of the positoon
if(plotIgnoreDistance==1)
    figure;
    hold all;
    for(currResult=1:numOfResults)
        clear cdfSetSize legendName;
        setSizeToPlot=resultList{currResult};
        setSizeToPlot=reshape(setSizeToPlot,size(setSizeToPlot,1)*size(setSizeToPlot,2),1);
        %We filter out those with set size 0 as these are invalid elements
        setSizeToPlot=setSizeToPlot(setSizeToPlot>0);

        for(i=1:size(logxAxis,2))
            cdfSetSize(i)= sum(setSizeToPlot<=logxAxis(i))/size(setSizeToPlot,1);
        end
        plot(cdfSetSize,markerIndces{currResult}, 'LineWidth',theLineWidth,'MarkerSize',theMarkerWidth) 
    end

    title({titleFirst; titleSecond});
    %title({titleFirst});
    ax=gca;
    ax.FontSize=14;
    legendName=experimentNames;
    legend(legendName);
    legend('Location','best')   
    if(isIP==1||isIP==4)
       xlabel('anonymity set-size (client IPv4 address)')
    else
        xlabel('anonymity set-size (entry AS)')
    end
    ylabel('probability')
    xlim(xlimValue)
    xticks(xticksValues)
    xticklabels(xtickString)
    ylim(ylimValue)
    yticks(yticksValues)
    print(fileName+"IgnoreDistance",'-dpng')

end
%  
%  
%  %%Plotting The difference, take the first as reference
%  %% Now we plot same distance but different results
% if(plotPerDistance==1)
%     
%     for(currDistance=1:distanceBound)
%         figure;
%         hold all;
%         clear legendName referenceCdfSetSize;
%         setSizeToPlot=resultList{currResult};
%         validEntries=setSizeToPlot(setSizeToPlot(:,currDistance)>0,currDistance);
%         numOfEntries=size(validEntries,1);
%         if(numOfEntries>0)
%             for(i=1:size(logxAxis,2))
%                 referenceCdfSetSize(i)= sum(validEntries<=logxAxis(i))/numOfEntries;
%             end
%         end
%             
%         for(currResult=2:numOfResults)
%             clear cdfSetSize;
%             setSizeToPlot=resultList{currResult};
%             validEntries=setSizeToPlot(setSizeToPlot(:,currDistance)>0,currDistance);
%             numOfEntries=size(validEntries,1);
%             if(numOfEntries>0)
%                 for(i=1:size(logxAxis,2))
%                     cdfSetSize(i)= sum(validEntries<=logxAxis(i))/numOfEntries;
%                 end
%                 legendName{currResult-1}=experimentNames{currResult}+"("+num2str(numOfEntries)+")";
%             end
%             plot(cdfSetSize-referenceCdfSetSize,markerIndces{currResult-1}, 'LineWidth',theLineWidth,'MarkerSize',theMarkerWidth) 
%         end
%         plot(cdfSetSize)  
%         xlim(xlimValue)
%         xticks(xticksValues)
%         xticklabels(xtickString)
%                 ylim(ylimValue)
%         yticks(yticksValues)
%         legend(legendName);
%         legend('Location','best')   
%        xlabel('anonymity set-size')
%         ylabel('probability')
%         title(titleFirst+experimentNames{1}+titleSecond+num2str(currDistance));
%          ax=gca;
%         ax.FontSize=14;
%     end
% end


end